import io
import re
import zipfile
from collections import Counter
from collections.abc import Iterable
from datetime import UTC, date, datetime, timedelta
from decimal import Decimal, InvalidOperation
from xml.etree.ElementTree import Element, ParseError

from defusedxml import DefusedXmlException
from defusedxml.ElementTree import fromstring

from filevet.core.analyzer import AnalysisContext, AnalyzerResult, Party
from filevet.core.artifact import Artifact
from filevet.core.extract_finance import (
    IBAN_LENGTHS,
    Found,
    amounts,
    bic_problem,
    column,
    compact,
    dates,
    from_iso20022,
    from_table,
    from_text,
    iban_problem,
    local,
    mask,
    read_csv,
    read_xlsx,
    walk,
)
from filevet.core.finding import Finding, Location, Severity
from filevet.core.identify import iso20022_message
from filevet.core.pdf import Pdf, lines

MAX_FINDINGS = 50
BOOKING_TOLERANCE = timedelta(days=7)
TOTAL = re.compile(
    r"(?i)\b(grand total|total due|amount due|total|gesamtbetrag|rechnungsbetrag|importe total)\b"
)
SUBTOTAL = re.compile(r"(?i)\b(sub-?total|net total|zwischensumme|nettobetrag)\b")
TAX = re.compile(r"(?i)\b(vat|tax|mwst|ust|iva|tva)\b")
OPENING = re.compile(r"(?i)\b(opening|previous|anfangssaldo|saldo inicial|solde initial)\b")
CLOSING = re.compile(r"(?i)\b(closing|new balance|endsaldo|schlusssaldo|saldo final|solde final)\b")
IDS = ("MsgId", "PmtInfId", "InstrId", "EndToEndId", "TxId", "NtryRef", "AcctSvcrRef")
TRANSACTIONS = ("CdtTrfTxInf", "DrctDbtTxInf")
REFERENCES = ["https://www.iso20022.org/iso-20022-message-definitions"]

Scope = tuple[str, list[Found]]


class FinancialData:
    name = "integrity.financial_data"
    version = "0.1.0"

    def supports(self, artifact: Artifact) -> bool:
        return artifact.detected_type in {"pdf", "text", "xml", "zip"}

    def analyze(self, artifact: Artifact, ctx: AnalysisContext) -> AnalyzerResult:
        data = artifact.read(ctx.limits.max_input_bytes)
        try:
            findings = _check(artifact.detected_type, data, ctx)
        except (ValueError, IndexError, KeyError, OverflowError, RecursionError) as exc:
            findings = [
                Finding(
                    rule_id="parser.malformed",
                    title="File could not be read for financial data checks",
                    description=f"Reading failed: {type(exc).__name__}. The checks did not run.",
                    severity=Severity.MEDIUM,
                    evidence=type(exc).__name__,
                )
            ]
        if ctx.mask:
            findings = [f.model_copy(update={"evidence": mask(f.evidence)}) for f in findings]
        return AnalyzerResult(findings=findings[:MAX_FINDINGS])


def _check(kind: str, data: bytes, ctx: AnalysisContext) -> list[Finding]:
    if kind == "xml":
        return _xml(data, ctx)
    if kind == "zip":
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                if "xl/workbook.xml" not in zf.namelist():
                    return []
                sheets = read_xlsx(zf, ctx.limits.max_input_bytes)
        except (zipfile.BadZipFile, OSError, EOFError):
            return []
        return [f for sheet, rows in sheets.items() for f in _table(rows, sheet, ctx)]
    if kind == "pdf":
        pdf = Pdf(data, ctx.limits.max_total_expanded_bytes)
        if pdf.encrypted:
            return []
        text = [line.split("\t", 1)[1] for line in lines(pdf.pages(len(pdf.ends) - 1))]
        return _text(text, ctx)
    rows = read_csv(data)
    if rows and sum(len(r) > 1 for r in rows) > len(rows) / 2:
        return _table(rows, None, ctx)
    return _text(data.decode("utf-8", "replace").splitlines(), ctx)


def _text(text: list[str], ctx: AnalysisContext) -> list[Finding]:
    ibans: list[Found] = []
    bics: list[Found] = []
    for number, line in enumerate(text, 1):
        found_ibans, found_bics = from_text(line, Location(offset=number))
        ibans += found_ibans
        bics += found_bics
    findings = _identifiers(ibans, bics)
    labeled = sorted({i.value for i in ibans if i.labeled and iban_problem(i.value) is None})
    if len(labeled) > 1:
        why = "The document gives more than one IBAN to pay into."
        findings.append(
            _finding(
                "iban_inconsistent",
                "Several beneficiary IBANs",
                why,
                Severity.MEDIUM,
                ", ".join(labeled),
            )
        )
    single_bic = len({b.value for b in bics}) == 1 and bic_problem(bics[0].value) is None
    if single_bic and len(labeled) == 1 and bics[0].value[4:6] != labeled[0][:2]:
        why = "The bank's BIC is in a different country from the IBAN."
        findings.append(
            _finding(
                "bic_invalid",
                "BIC and IBAN countries differ",
                why,
                Severity.LOW,
                f"{bics[0].value} / {labeled[0]}",
            )
        )
    findings += _allowlist([("\n".join(text), ibans)], ctx.expected.parties)
    findings += _text_totals(text)
    findings += _impossible_dates((Location(offset=n), line) for n, line in enumerate(text, 1))
    return findings


def _table(rows: list[list[str]], sheet: str | None, ctx: AnalysisContext) -> list[Finding]:
    ibans, bics = from_table(rows, sheet)
    by_row: dict[int, list[Found]] = {}
    for iban in ibans if ctx.expected.parties else []:
        by_row.setdefault(int(re.sub(r"[A-Z]", "", iban.location.cell or "0")), []).append(iban)
    scopes = [(" ".join(rows[r - 1]), found) for r, found in by_row.items()]
    cells = (
        (Location(sheet=sheet, cell=f"{column(c)}{r}"), value)
        for r, row in enumerate(rows, 1)
        for c, value in enumerate(row, 1)
        if any(parsed is None for _, parsed in dates(value))
    )
    return [
        *_identifiers(ibans, bics),
        *_allowlist(scopes, ctx.expected.parties),
        *_impossible_dates(cells),
    ]


def _identifiers(ibans: list[Found], bics: list[Found]) -> list[Finding]:
    findings = []
    for iban in ibans:
        problem = iban_problem(iban.value)
        right_length = len(iban.value) == IBAN_LENGTHS.get(iban.value[:2])
        if problem and (iban.labeled or right_length):
            findings.append(
                _finding(
                    "iban_invalid",
                    "IBAN is not valid",
                    f"The IBAN fails its checks: {problem}.",
                    Severity.MEDIUM,
                    iban.value,
                    iban.location,
                )
            )
    for bic in bics:
        problem = bic_problem(bic.value)
        if problem:
            findings.append(
                _finding(
                    "bic_invalid",
                    "BIC is not valid",
                    f"The BIC fails ISO 9362: {problem}.",
                    Severity.LOW,
                    bic.value,
                    bic.location,
                )
            )
    return findings


def _allowlist(scopes: list[Scope], parties: dict[str, Party]) -> list[Finding]:
    findings = []
    for text, ibans in scopes:
        folded = text.casefold()
        for party_name, party in parties.items():
            if not party.ibans or party_name.casefold() not in folded:
                continue
            known = {compact(i) for i in party.ibans}
            for iban in ibans:
                if iban.value not in known and iban_problem(iban.value) is None:
                    why = "The document names a known supplier, but not with its IBAN on record."
                    findings.append(
                        _finding(
                            "iban_not_allowlisted",
                            "IBAN not on record for this supplier",
                            why,
                            Severity.MEDIUM,
                            iban.value,
                            iban.location,
                        )
                    )
    return findings


def _text_totals(text: list[str]) -> list[Finding]:
    opening = closing = total = subtotal = None
    items: list[Decimal] = []
    entries: list[Decimal] = []
    taxes: list[Decimal] = []
    for line in text:
        values = amounts(line)
        if not values:
            continue
        if OPENING.search(line):
            opening = values[-1]
        elif CLOSING.search(line):
            closing = values[-1]
            break
        elif SUBTOTAL.search(line):
            subtotal = values[-1]
        elif TAX.search(line):
            taxes.append(values[-1])
        elif TOTAL.search(line):
            total = values[-1]
            break
        else:
            items.append(values[-1])
            entries.append(values[0])
    if opening is not None and closing is not None:
        if entries and any(e < 0 for e in entries) and opening + sum(entries) != closing:
            why = "The opening balance plus the entries does not give the closing balance."
            evidence = f"{opening} + {sum(entries)} != {closing}"
            return [
                _finding(
                    "totals_mismatch",
                    "Statement does not reconcile",
                    why,
                    Severity.MEDIUM,
                    evidence,
                )
            ]
        return []
    if total is None or len(items) < 2:
        return []
    tax = sum(taxes, Decimal(0))
    sums = {sum(items), sum(items) + tax}
    if subtotal is not None:
        sums.add(subtotal + tax)
    if total in sums and (subtotal is None or subtotal == sum(items)):
        return []
    why = "The line items do not add up to the stated total."
    evidence = f"items {sum(items)}, tax {tax}, total {total}"
    return [
        _finding(
            "totals_mismatch",
            "Invoice total does not match its lines",
            why,
            Severity.MEDIUM,
            evidence,
        )
    ]


def _impossible_dates(cells: Iterable[tuple[Location, str]]) -> list[Finding]:
    findings: list[Finding] = []
    for location, value in cells:
        for raw, parsed in dates(value):
            if parsed is None and len(findings) < 10:
                why = "The date does not exist in the calendar."
                findings.append(
                    _finding("date_anomaly", "Impossible date", why, Severity.MEDIUM, raw, location)
                )
    return findings


def _xml(data: bytes, ctx: AnalysisContext) -> list[Finding]:
    try:
        root = fromstring(data, forbid_dtd=True)
    except (ParseError, DefusedXmlException):
        return []
    message = iso20022_message(root.tag)
    if message is None:
        return []
    ibans, bics = from_iso20022(root)
    findings = _identifiers(ibans, bics)
    scopes = []
    for element in root.iter():
        if local(element) in (*TRANSACTIONS, "Ntry"):
            found, _ = from_iso20022(element)
            scopes.append((" ".join(element.itertext()), found))
    findings += _allowlist(scopes, ctx.expected.parties)
    findings += _duplicates(root, Severity.LOW if message.startswith("camt") else Severity.MEDIUM)
    if message.startswith(("camt.052", "camt.053")):
        findings += _balances(root)
    if message.startswith("camt"):
        findings += _camt_dates(root)
    else:
        findings += _control_sums(root)
    return findings


def _children(element: Element, name: str) -> list[Element]:
    return [e for e in element if local(e) == name]


def _find(element: Element, path: str) -> Element | None:
    for step in path.split("/"):
        found = _children(element, step)
        if not found:
            return None
        element = found[0]
    return element


def _decimal(element: Element | None) -> Decimal | None:
    try:
        return Decimal((element.text or "").strip()) if element is not None else None
    except InvalidOperation:
        return None


def _signed(element: Element) -> Decimal | None:
    value = _decimal(_find(element, "Amt"))
    indicator = _find(element, "CdtDbtInd")
    if value is None:
        return None
    return -value if indicator is not None and (indicator.text or "").strip() == "DBIT" else value


def _duplicates(root: Element, severity: Severity) -> list[Finding]:
    seen: Counter[tuple[str, str]] = Counter()
    for path, element in walk(root):
        tag = local(element)
        value = (element.text or "").strip()
        if tag in IDS and value and value != "NOTPROVIDED":
            seen[(path, value)] += 1
    findings = []
    for (path, value), count in seen.items():
        if count > 1:
            tag = path.rsplit("/", 1)[-1]
            why = f"{tag} {value} appears {count} times, which can mean a replayed payment."
            findings.append(
                _finding(
                    "duplicate_ids",
                    "Duplicate payment identifier",
                    why,
                    severity,
                    value,
                    Location(xpath=path),
                )
            )
    return findings


def _balances(root: Element) -> list[Finding]:
    findings = []
    for statement in root.iter():
        if local(statement) not in {"Stmt", "Rpt"}:
            continue
        balances: dict[str, Decimal] = {}
        for balance in _children(statement, "Bal"):
            code = _find(balance, "Tp/CdOrPrtry/Cd")
            value = _signed(balance)
            if code is not None and value is not None:
                balances.setdefault((code.text or "").strip(), value)
        opening = balances.get("OPBD", balances.get("PRCD"))
        closing = balances.get("CLBD")
        if opening is None or closing is None:
            continue
        booked = [_signed(e) for e in _children(statement, "Ntry") if _status(e) in {"", "BOOK"}]
        total = sum((v for v in booked if v is not None), Decimal(0))
        if opening + total != closing:
            why = "The opening balance plus the booked entries does not give the closing balance."
            evidence = f"{opening} + {total} != {closing}"
            findings.append(
                _finding(
                    "totals_mismatch",
                    "Statement balances do not reconcile",
                    why,
                    Severity.MEDIUM,
                    evidence,
                )
            )
    return findings


def _status(entry: Element) -> str:
    status = _find(entry, "Sts")
    return "".join(status.itertext()).strip() if status is not None else ""


def _control_sums(root: Element) -> list[Finding]:
    findings = []
    for block in root.iter():
        if local(block) not in {"GrpHdr", "PmtInf"}:
            continue
        scope = root if local(block) == "GrpHdr" else block
        txs = [e for e in scope.iter() if local(e) in TRANSACTIONS]
        values = []
        for tx in txs:
            amount = next(
                (e for e in tx.iter() if local(e) in {"InstdAmt", "IntrBkSttlmAmt"}), None
            )
            values.append(_decimal(amount) or Decimal(0))
        count = _find(block, "NbOfTxs")
        if count is not None and (count.text or "").strip() != str(len(txs)):
            stated = (count.text or "").strip()
            why = f"NbOfTxs says {stated}, but the message holds {len(txs)} transactions."
            findings.append(
                _finding(
                    "totals_mismatch",
                    "Transaction count does not match",
                    why,
                    Severity.MEDIUM,
                    f"{local(block)}/NbOfTxs",
                )
            )
        control = _decimal(_find(block, "CtrlSum"))
        if control is None:
            control = _decimal(_find(block, "TtlIntrBkSttlmAmt"))
        if control is not None and control != sum(values, Decimal(0)):
            why = "The control sum does not equal the sum of the transaction amounts."
            evidence = f"{local(block)}/CtrlSum {control} != {sum(values, Decimal(0))}"
            findings.append(
                _finding(
                    "totals_mismatch", "Control sum does not match", why, Severity.MEDIUM, evidence
                )
            )
    return findings


def _camt_dates(root: Element) -> list[Finding]:
    findings = []
    created = _datetime(_first(root, "CreDtTm"))
    now = datetime.now(UTC).date()
    if created and created > now + timedelta(days=1):
        findings.append(
            _finding(
                "date_anomaly",
                "Message created in the future",
                "The creation date is in the future.",
                Severity.MEDIUM,
                created.isoformat(),
            )
        )
    for statement in root.iter():
        if local(statement) not in {"Stmt", "Rpt", "Ntfctn"}:
            continue
        period = _find(statement, "FrToDt")
        start = _datetime(_first(period, "FrDtTm")) if period is not None else None
        end = _datetime(_first(period, "ToDtTm")) if period is not None else None
        for entry in _children(statement, "Ntry"):
            booked = _datetime(
                _first(_find(entry, "BookgDt"), "Dt") or _first(_find(entry, "BookgDt"), "DtTm")
            )
            value = _datetime(
                _first(_find(entry, "ValDt"), "Dt") or _first(_find(entry, "ValDt"), "DtTm")
            )
            if booked is None:
                continue
            problem = None
            if value and booked - value > BOOKING_TOLERANCE:
                problem = f"booked {booked}, value date {value}"
            elif start and end and not start <= booked <= end:
                problem = f"booked {booked}, outside the statement period {start} to {end}"
            elif created and booked > created + timedelta(days=1):
                problem = f"booked {booked}, after the message was created on {created}"
            if problem and len(findings) < 10:
                findings.append(
                    _finding(
                        "date_anomaly",
                        "Entry dates are inconsistent",
                        f"The entry is {problem}.",
                        Severity.MEDIUM,
                        problem,
                    )
                )
    return findings


def _first(element: Element | None, name: str) -> str | None:
    if element is None:
        return None
    found = next((e for e in element.iter() if local(e) == name), None)
    return (found.text or "").strip() if found is not None else None


def _datetime(value: str | None) -> date | None:
    if not value:
        return None
    try:
        return date.fromisoformat(value[:10])
    except ValueError:
        return None


def _finding(
    rule: str,
    title: str,
    description: str,
    severity: Severity,
    evidence: str,
    location: Location | None = None,
) -> Finding:
    return Finding(
        rule_id=f"integrity.{rule}",
        title=title,
        description=description,
        severity=severity,
        confidence=0.7,
        location=location,
        evidence=evidence,
        references=REFERENCES,
    )
