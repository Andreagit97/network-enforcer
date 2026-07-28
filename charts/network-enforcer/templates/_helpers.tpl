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
cniwatcher selector labels
*/}}
{{- define "network-enforcer.cniwatcher.selectorLabels" -}}
app.kubernetes.io/component: cniwatcher
{{ include "network-enforcer.selectorLabels" . }}
{{- end -}}

{{/*
This is used by the controller to list cniwatcher pods.
*/}}
{{- define "network-enforcer.cniwatcher.selectorLabelsString" -}}
  {{- $yaml := include "network-enforcer.cniwatcher.selectorLabels" . -}}
  {{- $m := (fromYaml $yaml) | default dict -}}
  {{- $keys := keys $m | sortAlpha -}}
  {{- $out := list -}}
  {{- range $k := $keys -}}
    {{- $out = append $out (printf "%s=%v" $k (get $m $k)) -}}
  {{- end -}}
  {{- join "," $out -}}
{{- end -}}

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
Path to the CA certificate (ca.crt) shared by the controller and cniwatcher
pods through their cert-manager CSI mount (network-enforcer.cniwatcher.certDir).
It is used to verify the shipped OTel collector's TLS certificate when
collectorStrategy == default.
*/}}
{{- define "network-enforcer.otel.caCertPath" -}}
{{ include "network-enforcer.cniwatcher.certDir" . }}/ca.crt
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
Certificate helpers for cniwatcher mTLS (CA issuer and secret share a name).
*/}}
{{- define "network-enforcer.caIssuerName" -}}
{{ include "network-enforcer.fullname" . }}-ca
{{- end -}}
{{- define "network-enforcer.caSecretName" -}}
{{ include "network-enforcer.fullname" . }}-ca
{{- end -}}
{{- define "network-enforcer.cniwatcher.certDir" -}}
/etc/network-enforcer/certs
{{- end -}}

{{/*
Certificate directory for OBI mTLS (shares the same CA as cniwatcher).
*/}}
{{- define "network-enforcer.obi.certDir" -}}
/etc/network-enforcer/certs
{{- end -}}

{{/*
CNI-specific volume mounts for cniwatcher
*/}}
{{- define "network-enforcer.cniwatcher.volumeMounts" -}}
{{- if eq .Values.cniwatcher.cniType "cilium" }}
- name: hubble-sock
  mountPath: /var/run/cilium
{{- else if eq .Values.cniwatcher.cniType "calico" }}
- name: goldmane-key-pair-volume
  mountPath: /etc/goldmane/certs
  readOnly: true
{{- else if eq .Values.cniwatcher.cniType "flannel" }}
- name: flannel-ulog
  mountPath: /var/log/ulog
  readOnly: true
{{- else if eq .Values.cniwatcher.cniType "aws-vpc" }}
- name: aws-eni-logs
  mountPath: /var/log/aws-routed-eni
  readOnly: true
{{- end }}
- name: cniwatcher-mtls-certs
  mountPath: {{ include "network-enforcer.cniwatcher.certDir" . }}
  readOnly: true
{{- end -}}

{{/*
CNI-specific volumes for cniwatcher
*/}}
{{- define "network-enforcer.cniwatcher.volumes" -}}
{{- if eq .Values.cniwatcher.cniType "cilium" }}
- name: hubble-sock
  hostPath:
    path: /var/run/cilium
{{- else if eq .Values.cniwatcher.cniType "calico" }}
- name: goldmane-key-pair-volume
  secret:
    secretName: cniwatcher-goldmane-key-pair
{{- else if eq .Values.cniwatcher.cniType "flannel" }}
- name: flannel-ulog
  hostPath:
    path: /var/log/ulog
    type: Directory
{{- else if eq .Values.cniwatcher.cniType "aws-vpc" }}
- name: aws-eni-logs
  hostPath:
    path: /var/log/aws-routed-eni
    type: Directory
{{- end }}
- name: cniwatcher-mtls-certs
  csi:
    driver: "csi.cert-manager.io"
    readOnly: true
    volumeAttributes:
      csi.cert-manager.io/issuer-name: {{ include "network-enforcer.caIssuerName" . }}
      csi.cert-manager.io/issuer-kind: Issuer
      csi.cert-manager.io/dns-names: ${POD_NAME}.${POD_NAMESPACE}
{{- end -}}
