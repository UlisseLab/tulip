import { createApi, fetchBaseQuery } from "@reduxjs/toolkit/query/react";

import { API_BASE_PATH } from "./const";
import type {
  Service,
  FullFlow,
  Signature,
  TickInfo,
  FlowsQuery,
  FlowsResponse,
} from "./types";

export const tulipApi = createApi({
  baseQuery: fetchBaseQuery({ baseUrl: API_BASE_PATH }),
  endpoints: (builder) => ({
    getServices: builder.query<Service[], void>({
      query: () => "/services",
    }),
    getFlagRegex: builder.query<string, void>({
      query: () => "/flag_regex",
    }),
    getFlow: builder.query<FullFlow, string>({
      query: (id) => `/flow/${id}`,
    }),
    getFlows: builder.query<FlowsResponse, FlowsQuery>({
      query: (query) => ({
        url: `/query`,
        method: "POST",
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        body: JSON.stringify(query),
      }),
    }),
    getTags: builder.query<string[], void>({
      query: () => `/tags`,
    }),
    getTickInfo: builder.query<TickInfo, void>({
      query: () => `/tick_info`,
    }),
    getSignature: builder.query<Signature[], number>({
      query: (id) => `/signature/${id}`,
    }),
    toPwnTools: builder.query<string, string>({
      query: (id) => ({ url: `/to_pwn/${id}`, responseHandler: "text" }),
    }),
    toSinglePythonRequest: builder.query<
      string,
      { body: string; id: string; tokenize: boolean }
    >({
      query: ({ body, id, tokenize }) => ({
        url: `/to_single_python_request?tokenize=${
          tokenize ? "1" : "0"
        }&id=${id}`,
        method: "POST",
        responseHandler: "text",
        headers: {
          "Content-Type": "text/plain;charset=UTF-8",
        },
        body,
      }),
    }),
    toFullPythonRequest: builder.query<string, string>({
      query: (id) => ({
        url: `/to_python_request/${id}`,
        responseHandler: "text",
      }),
    }),
    starFlow: builder.mutation<unknown, { id: string; star: boolean }>({
      query: ({ id, star }) => ({
        url: `/star/${id}/${star ? "1" : "0"}`,
        method: "PATCH",
      }),
    }),
    getFingerprints: builder.query<number[], void>({
      query: () => `/fingerprints`,
    }),
  }),
});

export const {
  useGetServicesQuery,
  useGetFlagRegexQuery,
  useGetFlowQuery,
  useGetFlowsQuery,
  useLazyGetFlowsQuery,
  useGetTagsQuery,
  useGetSignatureQuery,
  useGetTickInfoQuery,
  useLazyToPwnToolsQuery,
  useLazyToFullPythonRequestQuery,
  useToSinglePythonRequestQuery,
  useStarFlowMutation,
  useGetFingerprintsQuery,
} = tulipApi;
