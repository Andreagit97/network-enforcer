{{/*
Expand the name of the chart.
*/}}
{{- define "network-enforcer.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "network-enforcer.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "network-enforcer.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "network-enforcer.labels" -}}
helm.sh/chart: {{ include "network-enforcer.chart" . }}
{{ include "network-enforcer.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "network-enforcer.selectorLabels" -}}
app.kubernetes.io/name: {{ include "network-enforcer.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}


{{/*
DNS name of the controller OTLP service; also a SAN on the controller cert.
*/}}
{{- define "network-enforcer.controller.otlpServiceDNS" -}}
{{ include "network-enforcer.fullname" . }}-otlp.{{ .Release.Namespace }}.svc.cluster.local
{{- end -}}

{{/*
Certificate directory for the shipped OTel collector's own (server-side) mTLS
keys, mounted via cert-manager CSI.
*/}}
{{- define "network-enforcer.otelCollector.certDir" -}}
/etc/otel-collector/certs
{{- end -}}


{{/*
Print the otel environment variable settings.
*/}}
{{- define "network-enforcer.otel.config.env" }}
{{- if eq .Values.telemetry.collectorStrategy "default" }}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: https://{{ include "network-enforcer.fullname" . }}-otel-collector.{{ .Release.Namespace }}.svc.cluster.local:4317
- name: OTEL_EXPORTER_OTLP_PROTOCOL
  value: grpc
- name: OTEL_EXPORTER_OTLP_CERTIFICATE
  value: {{ include "network-enforcer.otel.caCertPath" . }}
{{- else if eq .Values.telemetry.collectorStrategy "external" }}
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: {{ .Values.telemetry.externalCollector.endpoint }}
- name: OTEL_EXPORTER_OTLP_PROTOCOL
  value: {{ .Values.telemetry.externalCollector.protocol }}
{{- if .Values.telemetry.externalCollector.otelCollectorCertificateSecret }}
- name: OTEL_EXPORTER_OTLP_CERTIFICATE
  value: /tmp/otel-collector-certs/ca.crt
{{- else }}
- name: OTEL_EXPORTER_OTLP_INSECURE
  value: "true"
{{- end }}
{{- if .Values.telemetry.externalCollector.otelCollectorClientCertificateSecret }}
- name: OTEL_EXPORTER_OTLP_CLIENT_CERTIFICATE
  value: /tmp/otel-collector-client-certs/tls.crt
- name: OTEL_EXPORTER_OTLP_CLIENT_KEY
  value: /tmp/otel-collector-client-certs/tls.key
{{- end }}
{{- end }}
{{- end }}

{{/*
Print the otel volumeMounts settings (only relevant for the external strategy).
The strategy gate mirrors network-enforcer.otel.config.volumes so mounts and
volumes are always emitted (or omitted) as a pair.
*/}}
{{- define "network-enforcer.otel.config.volumeMounts" }}
{{- if and (eq .Values.telemetry.collectorStrategy "external") .Values.telemetry.externalCollector.otelCollectorCertificateSecret }}
- name: otel-collector-ca-cert
  mountPath: /tmp/otel-collector-certs
  readOnly: true
{{- end }}
{{- if and (eq .Values.telemetry.collectorStrategy "external") .Values.telemetry.externalCollector.otelCollectorClientCertificateSecret }}
- name: otel-collector-client-cert
  mountPath: /tmp/otel-collector-client-certs
  readOnly: true
{{- end }}
{{- end }}

{{/*
Print the otel volumes settings (only relevant for the external strategy).
*/}}
{{- define "network-enforcer.otel.config.volumes" }}
{{- if and (eq .Values.telemetry.collectorStrategy "external") .Values.telemetry.externalCollector.otelCollectorCertificateSecret }}
- name: otel-collector-ca-cert
  secret:
    secretName: {{ .Values.telemetry.externalCollector.otelCollectorCertificateSecret }}
{{- end }}
{{- if and (eq .Values.telemetry.collectorStrategy "external") .Values.telemetry.externalCollector.otelCollectorClientCertificateSecret }}
- name: otel-collector-client-cert
  secret:
    secretName: {{ .Values.telemetry.externalCollector.otelCollectorClientCertificateSecret }}
{{- end }}
{{- end }}

{{/*
Certificate helpers for mTLS (CA issuer and secret share a name).
*/}}
{{- define "network-enforcer.caIssuerName" -}}
{{ include "network-enforcer.fullname" . }}-ca
{{- end -}}
{{- define "network-enforcer.caSecretName" -}}
{{ include "network-enforcer.fullname" . }}-ca
{{- end -}}
