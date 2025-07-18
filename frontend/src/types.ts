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
  parent_id: Id;
  child_id: Id;
  tags: string[];
  flags: string[];
  flagids: string[];
  suricata: number[];
  filename: string;
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
  // Text filter
  "flow.data"?: string;
  service: string;
  dst_ip?: string; // TODO: remove this, use service
  dst_port?: number; // TODO: remove this, use service
  from_time?: number;
  to_time?: number;
  includeTags: string[];
  excludeTags: string[];
  tags: string[];
  flags: string[];
  flagids: string[];
  limit?: number;
  offset?: number;
};

export type Service = {
  ip: string;
  port: number;
  name: string;
};
