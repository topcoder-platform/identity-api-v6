export interface EventPayload {
  topic: string;
  originator: string;
  timestamp: string; // ISO 8601 format UTC
  'mime-type': string;
  payload: any; // The actual event data
}
