import { useSearchParams, useParams, useNavigate } from "react-router";
import React, { useEffect, useState } from "react";
import { useHotkeys } from "react-hotkeys-hook";
import type { FlowData, FullFlow } from "../types";
import { Buffer } from "buffer";
import {
  TEXT_FILTER_KEY,
  MAX_LENGTH_FOR_HIGHLIGHT,
  API_BASE_PATH,
} from "../const";
import {
  ArrowLeftCircleIcon,
  ArrowRightCircleIcon,
  ArrowDownTrayIcon,
} from "@heroicons/react/24/solid";
import { format } from "date-fns";

import { hexy } from "hexy";
import { useCopy } from "../hooks/useCopy";
import { RadioGroup } from "../components/RadioGroup";
import {
  useGetFlowQuery,
  useLazyToFullPythonRequestQuery,
  useLazyToPwnToolsQuery,
  useToSinglePythonRequestQuery,
  useGetFlagRegexQuery,
} from "../api";
import escapeStringRegexp from "escape-string-regexp";

const SECONDARY_NAVBAR_HEIGHT = 50;

function openInCyberChef(b64: string) {
  return window.open(
    "https://gchq.github.io/CyberChef/#input=" + encodeURIComponent(b64),
  );
}

function CopyButton({ copyText }: { copyText?: string }) {
  const { copy } = useCopy({
    getText: async () => copyText ?? "",
  });

  if (copyText == null || copyText === "") {
    return <></>;
  }

  return (
    <button
      type="button"
      className="p-2 text-sm text-blue-500 dark:text-blue-400 hover:bg-blue-50 dark:hover:bg-blue-900 cursor-pointer"
      onClick={copy}
      disabled={!copyText}
    >
      Copy
    </button>
  );
}

function FlowContainer({
  copyText,
  children,
}: {
  copyText?: string;
  children: React.ReactNode;
}) {
  return (
    <div className="pb-5 flex flex-col border border-gray-300 dark:border-gray-700 bg-gray-50 dark:bg-gray-900/70 text-gray-800 dark:text-gray-100 shadow-sm">
      <div className="ml-auto">
        <CopyButton copyText={copyText}></CopyButton>
      </div>
      <pre className="p-5 overflow-auto">{children}</pre>
    </div>
  );
}

function HexFlow({ flow }: { flow: FlowData }) {
  const hex = hexy(Buffer.from(flow.b64, "base64"), { format: "twos" });
  return <FlowContainer copyText={hex}>{hex}</FlowContainer>;
}

function fastTextHash(text: string): string {
  let hash = 0;
  for (let i = 0; i < text.length; i++) {
    hash = (hash << 5) - hash + text.charCodeAt(i);
    hash |= 0; // Convert to 32bit integer
  }
  return hash.toString(16); // Convert to hexadecimal string
}

function highlightText(
  flowText: string,
  search_string: string,
  flag_string: string,
) {
  if (flowText.length > MAX_LENGTH_FOR_HIGHLIGHT || (flag_string === "" && search_string === "")) {
    return flowText;
  }
  try {
    let search_regex: RegExp | null = null;
    if (search_string !== "") {
      // Usa sempre escapeStringRegexp per ricerca letterale
      search_regex = new RegExp(escapeStringRegexp(search_string), "gi");
    }
    let flag_regex: RegExp | null = null;
    if (flag_string !== "") {
      try {
        flag_regex = new RegExp(flag_string, "g");
      } catch (e) {
        flag_regex = null;
      }
    }
    // Costruisci una regex combinata per trovare tutti i match
    let combined_regex: RegExp | null = null;
    if (search_regex && flag_regex) {
      combined_regex = new RegExp(`(${search_regex.source})|(${flag_regex.source})`, "gi");
    } else if (search_regex) {
      combined_regex = search_regex;
    } else if (flag_regex) {
      combined_regex = flag_regex;
    }
    if (!combined_regex) return flowText;
    const result: React.ReactNode[] = [];
    let lastIndex = 0;
    let match;
    let idx = 0;
    while ((match = combined_regex.exec(flowText)) !== null) {
      if (match.index > lastIndex) {
        result.push(flowText.slice(lastIndex, match.index));
      }
      let className = "";
      if (search_regex && match[1]) {
        className = "bg-orange-200 dark:bg-orange-900 rounded-sm";
      } else if (flag_regex && match[2]) {
        className = "bg-red-200 dark:bg-red-900 rounded-sm";
      }
      result.push(
        <span key={idx++ + '-' + match.index} className={className}>{match[0]}</span>
      );
      lastIndex = combined_regex.lastIndex;
    }
    if (lastIndex < flowText.length) {
      result.push(flowText.slice(lastIndex));
    }
    return <span>{result}</span>;
  } catch (error) {
    console.log(error);
    return flowText;
  }
}

function TextFlow({ flow }: { flow: FlowData }) {
  const [searchParams] = useSearchParams();
  const textFilter = searchParams.get(TEXT_FILTER_KEY);

  const { data: flagRegex } = useGetFlagRegexQuery();

  const text = highlightText(flow.data, textFilter ?? "", flagRegex ?? "");

  return <FlowContainer copyText={flow.data}>{text}</FlowContainer>;
}

function WebFlow({ flow }: { flow: FlowData }) {
  const data = flow.data;

  const [header, ...rest] = data.split("\r\n\r\n");
  const httpContent = rest.join("\r\n\r\n");

  return (
    <FlowContainer>
      <pre>{header}</pre>
      <div className="border border-gray-200 dark:border-gray-700 rounded-lg">
        <iframe
          srcDoc={httpContent}
          sandbox=""
          className="w-full"
          title="Web flow content"
        ></iframe>
      </div>
    </FlowContainer>
  );
}

function PythonRequestFlow({
  fullFlow,
  flow,
}: {
  fullFlow: FullFlow;
  flow: FlowData;
}) {
  const { data, error } = useToSinglePythonRequestQuery({
    body: flow.b64,
    id: fullFlow._id,
    tokenize: true,
  });

  return error ? (
    <FlowContainer>
      <span className="text-red-500 dark:text-red-400">
        Error generating Python request: {JSON.stringify(error)}
      </span>
    </FlowContainer>
  ) : (
    <FlowContainer copyText={data}>{data}</FlowContainer>
  );
}

function detectType(flow: FlowData) {
  const firstLine = flow.data.split("\n")[0];
  if (firstLine.includes("HTTP")) {
    return "Web";
  }

  return "Plain";
}

function getFlowBody(flow: FlowData, flowType: string) {
  if (flowType == "Web") {
    const contentType = flow.data.match(/Content-Type: ([^\s;]+)/im)?.[1];
    if (contentType) {
      const body = Buffer.from(flow.b64, "base64").subarray(
        flow.data.indexOf("\r\n\r\n") + 4,
      );
      return [contentType, body];
    }
  }
  return null;
}

function downloadBlob(
  dataBase64: string,
  id: string,
  type = "application/octet-stream",
) {
  const blob = new Blob([Buffer.from(dataBase64, "base64")], { type });
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.style.display = "none";
  a.href = url;
  a.download = "tulip-dl-" + id + ".dat";
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  a.remove();
}

type FlowProps = {
  full_flow: FullFlow;
  flow: FlowData;
  delta_time: number;
  id: string;
};

function Flow({ full_flow, flow, delta_time, id }: FlowProps) {
  const formatted_time = format(new Date(flow.time), "HH:mm:ss:SSS");
  const displayOptions = ["Plain", "Hex", "Web", "PythonRequest"];

  // Basic type detection, currently unused
  const [displayOption, setDisplayOption] = useState("Plain");

  const [collapsed, setCollapsed] = useState(false);

  const flowType = detectType(flow);
  const flowBody = getFlowBody(flow, flowType);

  return (
    <div className="text-mono" id={id}>
      <div
        className="sticky shadow bg-gray-50 dark:bg-gray-900/70 overflow-auto py-1 border border-gray-300 dark:border-gray-700 top-12 cursor-pointer select-none flex items-center h-6 gap-2"
        onClick={() => setCollapsed((c) => !c)}
        title={collapsed ? "Espandi richiesta" : "Chiudi richiesta"}
        style={{ userSelect: "none" }}
      >
        <span className="w-6 flex items-center justify-center">
          {collapsed ? (
            <span className="text-lg">▶</span>
          ) : (
            <span className="text-lg">▼</span>
          )}
        </span>
        <div className="w-8 px-2">
          {flow.from === "s" ? (
            <ArrowLeftCircleIcon className="fill-green-700 dark:fill-green-400" />
          ) : (
            <ArrowRightCircleIcon className="fill-red-700 dark:fill-red-400" />
          )}
        </div>
        <div className="w-52">
          <span className="font-bold text-gray-800 dark:text-gray-100">
            {formatted_time}
          </span>
          <span className="text-gray-400 dark:text-gray-300 pl-3">
            {delta_time}ms
          </span>
        </div>
        <div className="flex gap-2 ml-2">
          <button
            type="button"
            className="py-1 px-2 rounded-md text-sm border border-gray-300 dark:border-gray-700 bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-100 hover:bg-gray-200 dark:hover:bg-gray-700 cursor-pointer transition-colors"
            onClick={(e) => {
              e.stopPropagation();
              openInCyberChef(flow.b64);
            }}
          >
            Open in CyberChef
          </button>
          {flowBody && (
            <button
              type="button"
              className="py-1 px-2 rounded-md text-sm border border-gray-300 dark:border-gray-700 bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-100 hover:bg-gray-200 dark:hover:bg-gray-700 cursor-pointer ml-2 transition-colors"
              onClick={(e) => {
                e.stopPropagation();
                openInCyberChef(flowBody[1].toString("base64"));
              }}
            >
              Open body in CyberChef
            </button>
          )}
          <button
            type="button"
            className="py-1 px-2 rounded-md text-sm border border-gray-300 dark:border-gray-700 bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-100 hover:bg-gray-200 dark:hover:bg-gray-700 cursor-pointer ml-2 transition-colors"
            onClick={(e) => {
              e.stopPropagation();
              downloadBlob(flow.b64, id, "application/octet-stream");
            }}
          >
            Download raw
          </button>
          {flowBody && (
            <button
              type="button"
              className="py-1 px-2 rounded-md text-sm border border-gray-300 dark:border-gray-700 bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-100 hover:bg-gray-200 dark:hover:bg-gray-700 cursor-pointer ml-2 transition-colors"
              onClick={(e) => {
                e.stopPropagation();
                downloadBlob(
                  flowBody[1].toString("base64"),
                  id,
                  flowBody[0].toString(),
                );
              }}
            >
              Download body
            </button>
          )}
        </div>
        <div className="flex gap-2 text-gray-800 dark:text-gray-100 text-sm mr-4 ml-auto">
          <RadioGroup
            options={displayOptions}
            value={displayOption}
            onChange={setDisplayOption}
            className="flex gap-2 text-gray-800 dark:text-gray-100 text-sm"
          />
        </div>
      </div>
      {!collapsed && (
        <div
          className={
            flow.from === "s"
              ? "border-l-8 border-green-300 dark:border-green-700"
              : "border-l-8 border-red-300 dark:border-red-700"
          }
        >
          {displayOption === "Hex" && <HexFlow flow={flow}></HexFlow>}
          {displayOption === "Plain" && <TextFlow flow={flow}></TextFlow>}
          {displayOption === "Web" && <WebFlow flow={flow}></WebFlow>}
          {displayOption === "PythonRequest" && (
            <PythonRequestFlow
              flow={flow}
              fullFlow={full_flow}
            ></PythonRequestFlow>
          )}
        </div>
      )}
    </div>
  );
}

// Helper function to format the IP for display. If the IP contains ":",
// assume it is an ipv6 address and surround it in square brackets
function formatIP(ip: string) {
  return ip.includes(":") ? `[${ip}]` : ip;
}

function FlowOverview({ flow }: { flow: FullFlow }) {
  const FILTER_KEY = TEXT_FILTER_KEY;

  const [searchParams, setSearchParams] = useSearchParams();

  return (
    <div>
      {(flow.signatures?.length ?? 0) <= 0 ? undefined : (
        <div className="bg-blue-200 p-2">
          <div className="font-extrabold">Suricata</div>

          <table
            className="border-separate"
            style={{
              borderSpacing: "1em 0",
            }}
          >
            <thead>
              <tr className="text-left">
                <th>Rule ID</th>
                <th>Message</th>
                <th>Action taken</th>
              </tr>
            </thead>
            <tbody>
              {flow.signatures.map((sig) => {
                return (
                  <tr key={sig.id}>
                    <td className="text-right">
                      <code>{sig.id}</code>
                    </td>
                    <td>{sig.msg}</td>
                    <td
                      className={
                        sig.action === "blocked"
                          ? "font-bold text-right text-red-800"
                          : "font-bold text-right text-green-800"
                      }
                    >
                      {sig.action}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <div className="bg-yellow-200 p-2 text-black dark:bg-yellow-800 dark:text-gray-100">
        <div className="font-extrabold">Meta</div>
        <div className="pl-2 grid grid-cols-[max-content_1fr] gap-x-4">
          <span className="text-right">Flow ID: </span>
          <span>{flow._id}</span>

          <span className="text-right">Source: </span>
          <span>
            <a
              className="underline"
              href={`${API_BASE_PATH}/download/?file=${flow.filename}`}
            >
              {flow.filename}
              <ArrowDownTrayIcon className="inline-flex items-baseline w-5 h-5" />
            </a>
          </span>

          <div className="text-right">Tags: </div>
          <div>[{flow.tags.join(", ")}]</div>

          <div className="text-right">Flags: </div>
          <div>
            [
            {flow.flags.map((query, i) => (
              <span key={query}>
                {i > 0 ? ", " : ""}
                <button
                  type="button"
                  className="underline hover:bg-gray-100 dark:hover:bg-gray-700 cursor-pointer"
                  title="Filter by this flag"
                  onClick={() => {
                    searchParams.set(FILTER_KEY, escapeStringRegexp(query));
                    setSearchParams(searchParams);
                  }}
                >
                  {query}
                </button>
              </span>
            ))}
            ]
          </div>
          <div className="text-right">Flag Ids: </div>
          <div className="">
            [
            {flow.flagids.map((query, i) => (
              <span key={query}>
                {i > 0 ? ", " : ""}
                <button
                  className="font-bold"
                  onClick={() => {
                    searchParams.set(FILTER_KEY, escapeStringRegexp(query));
                    setSearchParams(searchParams);
                  }}
                >
                  {query}
                </button>
                <span className="ml-1 text-blue-700" title="FlagId">🏷️</span>
              </span>
            ))}
            ]
          </div>

          <div className="text-right">Src → Dst (ms): </div>
          <div className="flex items-center gap-1">
            <span>{formatIP(flow.src_ip)}</span>:
            <span className="font-bold">{flow.src_port}</span>
            <span>→</span>
            <span>{formatIP(flow.dst_ip)}</span>:
            <span className="font-bold">{flow.dst_port}</span>
            <span className="italic">({flow.duration} ms)</span>
          </div>
        </div>
      </div>
    </div>
  );
}

export function FlowView() {
  const [searchParams] = useSearchParams();
  const params = useParams();
  const navigate = useNavigate();

  const id = params.id;

  const {
    data: flow,
    isError,
    isLoading,
  } = useGetFlowQuery(id!, { skip: id === undefined });

  const [triggerPwnToolsQuery] = useLazyToPwnToolsQuery();
  const [triggerFullPythonRequestQuery] = useLazyToFullPythonRequestQuery();

  async function copyAsPwn() {
    if (flow?._id) {
      const { data } = await triggerPwnToolsQuery(flow?._id);
      console.log(data);
      return data || "";
    }
    return "";
  }

  const { statusText: pwnCopyStatusText, copy: copyPwn } = useCopy({
    getText: copyAsPwn,
    copyStateToText: {
      copied: "Copied",
      default: "Copy as pwntools",
      failed: "Failed",
      copying: "Generating payload",
    },
  });

  async function copyAsRequests() {
    if (flow?._id) {
      const { data } = await triggerFullPythonRequestQuery(flow?._id);
      return data || "";
    }
    return "";
  }

  const { statusText: requestsCopyStatusText, copy: copyRequests } = useCopy({
    getText: copyAsRequests,
    copyStateToText: {
      copied: "Copied",
      default: "Copy as requests",
      failed: "Failed",
      copying: "Generating payload",
    },
  });

  // TODO: account for user scrolling - update currentFlow accordingly
  const [currentFlow, setCurrentFlow] = useState<number>(-1);

  useHotkeys(
    "h",
    () => {
      // we do this for the scroll to top
      if (currentFlow === 0) {
        document.getElementById(`${id}-${currentFlow}`)?.scrollIntoView(true);
      }
      setCurrentFlow((fi) => Math.max(0, fi - 1));
    },
    [currentFlow],
  );
  useHotkeys(
    "l",
    () => {
      if (currentFlow === (flow?.flow?.length ?? 1) - 1) {
        document.getElementById(`${id}-${currentFlow}`)?.scrollIntoView(true);
      }
      setCurrentFlow((fi) => Math.min((flow?.flow?.length ?? 1) - 1, fi + 1));
    },
    [currentFlow, flow?.flow?.length],
  );

  useEffect(() => {
    if (currentFlow < 0) {
      return;
    }
    document.getElementById(`${id}`)?.scrollIntoView(true);
  }, [currentFlow]);

  if (isError) {
    return (
      <div className="w-full h-full flex  justify-center items-center">
        <div>
          <h2 className="text-3xl font-bold mb-4">Error</h2>
          <p className="text-red-500 text-lg mb-2">
            Error fetching flow with id:
          </p>
          <code className="font-mono border border-gray-300 p-2 w-full block">
            {id}
          </code>
          <p className="text-gray-500 mt-4">
            Please check the id and try again.
          </p>
        </div>
      </div>
    );
  }

  if (isLoading || flow == undefined) {
    return (
      <div className="w-full h-full flex justify-center items-center">
        <div>
          <h2 className="text-6xl font-bold mb-4 animate-pulse">
            Loading flow...
          </h2>
        </div>
      </div>
    );
  }

  return (
    <div>
      <div
        className="sticky shadow-md top-0 bg-white overflow-auto border-b border-b-gray-300 flex z-100 dark:bg-gray-800 dark:border-gray-600"
        style={{ height: SECONDARY_NAVBAR_HEIGHT }}
      >
        {flow?.child_id != "000000000000000000000000" ||
        flow?.parent_id != "000000000000000000000000" ? (
          <div className="flex align-middle p-2 gap-3">
            <button
              type="button"
              className="bg-yellow-700 text-white px-2 text-sm rounded-md disabled:opacity-50 hover:bg-yellow-800 cursor-pointer"
              key={"parent" + flow.parent_id}
              disabled={flow?.parent_id === "000000000000000000000000"}
              onMouseDown={(e) => {
                if (e.button === 1) {
                  // handle opening in new tab
                  window.open(
                    `/flow/${flow.parent_id}?${searchParams}`,
                    "_blank",
                  );
                } else if (e.button === 0) {
                  navigate(`/flow/${flow.parent_id}?${searchParams}`);
                }
              }}
            >
              Parent
            </button>
            <button
              type="button"
              className="bg-yellow-700 text-white px-2 text-sm rounded-md disabled:opacity-50 hover:bg-yellow-800 cursor-pointer"
              key={"child" + flow.child_id}
              disabled={flow?.child_id === "000000000000000000000000"}
              onMouseDown={(e) => {
                if (e.button === 1) {
                  // handle opening in new tab
                  window.open(
                    `/flow/${flow.child_id}?${searchParams}`,
                    "_blank",
                  );
                } else if (e.button === 0) {
                  navigate(`/flow/${flow.child_id}?${searchParams}`);
                }
              }}
            >
              Child
            </button>
          </div>
        ) : undefined}
        <div className="flex align-middle p-2 gap-3 ml-auto">
          <button
            type="button"
            className="bg-gray-700 text-white px-2 text-sm rounded-md cursor-pointer hover:bg-gray-800 dark:hover:bg-gray-500 dark:bg-gray-700"
            onClick={copyPwn}
          >
            {pwnCopyStatusText}
          </button>

          <button
            type="button"
            className="bg-gray-700 text-white px-2 text-sm rounded-md cursor-pointer hover:bg-gray-800 dark:hover:bg-gray-500 dark:bg-gray-700"
            onClick={copyRequests}
          >
            {requestsCopyStatusText}
          </button>
        </div>
      </div>

      {flow ? <FlowOverview flow={flow}></FlowOverview> : undefined}
      <div key={flow._id}>
        {flow?.flow.map((flow_data, i, a) => {
          const delta_time = a[i].time - (a[i - 1]?.time ?? a[i].time);
          return (
            <Flow
              flow={flow_data}
              delta_time={delta_time}
              full_flow={flow}
              key={i}
              id={flow._id + "-" + i}
            />
          );
        })}
      </div>
    </div>
  );
}
