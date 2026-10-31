{{/*
Expand the name of the chart.
*/}}
{{- define "revoc.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a fully qualified app name, truncated to 63 chars (DNS naming spec).
*/}}
{{- define "revoc.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Chart name and version label.
*/}}
{{- define "revoc.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "revoc.labels" -}}
helm.sh/chart: {{ include "revoc.chart" . }}
{{ include "revoc.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "revoc.selectorLabels" -}}
app.kubernetes.io/name: {{ include "revoc.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Proxy component labels / selector labels.
*/}}
{{- define "revoc.proxy.labels" -}}
{{ include "revoc.labels" . }}
app.kubernetes.io/component: proxy
{{- end -}}

{{- define "revoc.proxy.selectorLabels" -}}
{{ include "revoc.selectorLabels" . }}
app.kubernetes.io/component: proxy
{{- end -}}

{{/*
Admin API component labels / selector labels.
*/}}
{{- define "revoc.admin.labels" -}}
{{ include "revoc.labels" . }}
app.kubernetes.io/component: admin-api
{{- end -}}

{{- define "revoc.admin.selectorLabels" -}}
{{ include "revoc.selectorLabels" . }}
app.kubernetes.io/component: admin-api
{{- end -}}

{{/*
Proxy and admin fully-qualified resource names.
*/}}
{{- define "revoc.proxy.fullname" -}}
{{- printf "%s-proxy" (include "revoc.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "revoc.admin.fullname" -}}
{{- printf "%s-admin" (include "revoc.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Service account name.
*/}}
{{- define "revoc.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "revoc.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Name of the secret holding REVOC credentials.
*/}}
{{- define "revoc.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-secrets" (include "revoc.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Postgres connection URL (rendered for use in env vars referencing the bundled chart).
*/}}
{{- define "revoc.postgresqlFullname" -}}
{{- printf "%s-postgresql" (include "revoc.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Redis connection host (rendered for use in env vars referencing the bundled chart).
*/}}
{{- define "revoc.redisFullname" -}}
{{- printf "%s-redis-master" (include "revoc.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
