export interface Flow {
  _id: Id;
  src_port: number;
  dst_port: number;
  src_ip: string;
  dst_ip: string;
  time: number;
  duration: number;
  // TODO: Get this from backend instead of hacky workaround
  service_tag: string;
  num_packets: number;
  tags: string[];
  flags: string[];
  flagids: string[];
  suricata: number[];
  filename: string;
  fingerprints: number[];
}

export interface TickInfo {
  startDate: string;
  tickLength: number;
}

export interface FullFlow extends Flow {
  signatures: Signature[];
  flow: FlowData[];
}

export type Id = string;

export interface FlowData {
  from: string;
  data: string;
  b64: string;
  time: number;
}

export interface Signature {
  id: number;
  msg: string;
  action: string;
}

export type FlowsQuery = {
  "flow.data"?: string; // Text filter
  service?: string;
  dst_ip?: string; // TODO: remove this, use service
  dst_port?: number; // TODO: remove this, use service
  from_time?: number;
  to_time?: number;
  includeTags?: string[];
  excludeTags?: string[];
  tags?: string[];
  flags?: string[];
  flagids?: string[];
  limit?: number;
  offset?: number;
  fingerprints?: number[];
};

export type FlowsResponse = {
  data: Flow[];
  page: number;
  count: number;
  items_per_page: number;
};

export type Service = {
  ip: string;
  port: number;
  name: string;
};
