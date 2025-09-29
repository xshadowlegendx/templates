{{- /* Custom Grype Template - Fully Compatible */ -}}
## 🛡️ Grype Scan Report

{{if eq .Source.Type "image" }}
Scan Target: `{{ .Source.Target.UserInput }}`
{{else}}
Scan Target: `{{ .Source.Target }}`
{{end}}

Scan Time: `{{ .Descriptor.Timestamp }}`

## 📊 Vulnerability Summary

{{- $critical := 0 -}}
{{- $high := 0 -}}
{{- $medium := 0 -}}
{{- $low := 0 -}}
{{- $negligible := 0 -}}
{{- $unknown := 0 -}}

{{- range .Matches }}
  {{- if eq .Vulnerability.Severity "Critical" }}{{ $critical = add $critical 1 }}{{ end }}
  {{- if eq .Vulnerability.Severity "High" }}{{ $high = add $high 1 }}{{ end }}
  {{- if eq .Vulnerability.Severity "Medium" }}{{ $medium = add $medium 1 }}{{ end }}
  {{- if eq .Vulnerability.Severity "Low" }}{{ $low = add $low 1 }}{{ end }}
  {{- if eq .Vulnerability.Severity "Negligible" }}{{ $negligible = add $negligible 1 }}{{ end }}
  {{- if eq .Vulnerability.Severity "Unknown" }}{{ $unknown = add $unknown 1 }}{{ end }}
{{- end }}

| Severity   | Count |
|------------|-------|
| Critical   | {{ $critical }} |
| High       | {{ $high }} |
| Medium     | {{ $medium }} |
| Low        | {{ $low }} |
| Negligible | {{ $negligible }} |
| Unknown    | {{ $unknown }} |

## 🔍 Top Critical & High Vulnerabilities

{{ $severities := list "Critical" "High" }}
{{- $shown := 0 }}
{{- range $severity := $severities }}
{{- range $.Matches }}
  {{- if eq .Vulnerability.Severity $severity }}
    {{- if lt $shown 10 }}
- **CVE:** `{{ .Vulnerability.ID }}`
- **Severity:** `{{ .Vulnerability.Severity }}`
- **EPSS Score:** `{{ if .Vulnerability.EPSS }}{{ printf "%.2f%%" (mulf (index .Vulnerability.EPSS 0).EPSS 100.0) }}{{ else }}N/A{{ end }}`
- **CVSS Score:** `{{ if .Vulnerability.Cvss }}{{ printf "%.2f" (index .Vulnerability.Cvss 0).Metrics.BaseScore }}{{ else }}N/A{{ end }}`
- **Package:** `{{ .Artifact.Name }}`
- **Installed Version:** `{{ .Artifact.Version }}`
- **Fixed Version:** {{ if .Vulnerability.Fix.Versions }}`{{ list .Vulnerability.Fix.Versions | join ", " }}`{{ else }}N/A{{ end }}
- **Description:** {{ trunc 200 .Vulnerability.Description }}
- - -
    {{- $shown = add $shown 1 }}
    {{- end }}
  {{- end }}
{{- end }}
{{- end }}
{{- if eq $shown 0 }}
#### ✅ No Critical or High vulnerabilities found.
{{- end }}
