export type Severity = "CRITICAL" | "HIGH" | "MEDIUM";

export interface CheckDefinition {
  id: string;
  title: string;
  severity: Severity;
  points: number;
  category: string;
  owasp?: string;
  cve?: string;
  cwe?: string;
  atlas?: string;
  nist?: string;
  description: string;
  steps: string[];
  fix: string;
}
