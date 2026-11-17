{{- define "filevet.fullname" -}}
{{- if contains .Chart.Name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "filevet.labels" -}}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{- end -}}

{{- define "filevet.selector" -}}
app.kubernetes.io/name: {{ .root.Chart.Name }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "filevet.image" -}}
{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}
{{- end -}}

{{- define "filevet.secretName" -}}
{{- .Values.existingSecret | default (include "filevet.fullname" .) -}}
{{- end -}}

{{- define "filevet.redisUrl" -}}
{{- if .Values.redis.enabled -}}
redis://{{ include "filevet.fullname" . }}-redis:6379/0
{{- else -}}
{{- required "set redis.externalUrl when redis.enabled is false" .Values.redis.externalUrl -}}
{{- end -}}
{{- end -}}

{{- define "filevet.env" -}}
- name: FILEVET_REDIS_URL
  value: {{ include "filevet.redisUrl" . | quote }}
- name: FILEVET_POLICY
  value: {{ .Values.policy | quote }}
- name: FILEVET_RETENTION_S
  value: {{ .Values.retentionSeconds | quote }}
- name: FILEVET_SPOOL_KEY
  valueFrom:
    secretKeyRef:
      name: {{ include "filevet.secretName" . }}
      key: FILEVET_SPOOL_KEY
- name: FILEVET_WEBHOOK_SECRET
  valueFrom:
    secretKeyRef:
      name: {{ include "filevet.secretName" . }}
      key: FILEVET_WEBHOOK_SECRET
      optional: true
{{- with .Values.webhook.hosts }}
- name: FILEVET_WEBHOOK_HOSTS
  value: {{ join "," . | quote }}
{{- end }}
{{- if .Values.clamav.enabled }}
- name: FILEVET_CLAMD
  value: tcp:{{ include "filevet.fullname" . }}-clamav:3310
{{- end }}
{{- with .Values.extraEnv }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "filevet.tmp" -}}
- name: tmp
  emptyDir:
    medium: Memory
    sizeLimit: {{ .Values.tmpSizeLimit }}
{{- end -}}
