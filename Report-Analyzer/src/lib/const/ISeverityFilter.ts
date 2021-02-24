import { SeverityLevelStrings } from './SeverityLevel';

export interface ISeverityFilter {
  alert: SeverityLevelStrings[];
  cve: SeverityLevelStrings[];
  certificate: SeverityLevelStrings[];
  crypto: SeverityLevelStrings[];
  deprecated: SeverityLevelStrings[];
  handshake: SeverityLevelStrings[];
  messagestructure: SeverityLevelStrings[];
  recordlayer: SeverityLevelStrings[];
  security: SeverityLevelStrings[];
  interoperability: SeverityLevelStrings[];
  compliance: SeverityLevelStrings[];
}
