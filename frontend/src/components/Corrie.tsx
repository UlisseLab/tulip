import { useSearchParams, useNavigate } from "react-router";
import { useCallback, useState, useEffect } from "react";
import type { Flow } from "../types";
import {
  SERVICE_FILTER_KEY,
  TEXT_FILTER_KEY,
  START_FILTER_KEY,
  END_FILTER_KEY,
  CORRELATION_MODE_KEY,
  FLOW_LIST_REFETCH_INTERVAL_MS,
  TAGS_FILTER_KEY,
  FLAGS_FILTER_KEY,
  FLAGIDS_FILTER_KEY,
} from "../const";
import useDebounce from "../hooks/useDebounce";

import ReactApexChart from "react-apexcharts";
import type { ApexOptions } from "apexcharts";
import { useGetFlowsQuery, useGetServicesQuery } from "../api";
import { useSearchParam } from "../store/param";

interface GraphProps {
  flowList: Flow[];
  mode: string;
  searchParams: URLSearchParams;
  setSearchParams: (a: URLSearchParams) => void;
  onClickNavigate: (a: string) => void;
}

// DeferredChart: delays rendering of children until browser is idle
function DeferredChart({ children }: { children: React.ReactNode }) {
  const [shouldRender, setShouldRender] = useState(false);

  useEffect(() => {
    if (window.requestIdleCallback) {
      // Use requestIdleCallback if available for better performance
      const handle = window.requestIdleCallback(() => setShouldRender(true));
      return () =>
        window.cancelIdleCallback && window.cancelIdleCallback(handle);
    } else {
      // Fallback to setTimeout if requestIdleCallback is not available
      const handle = setTimeout(() => setShouldRender(true), 1);
      return () => clearTimeout(handle);
    }
  }, []);

  if (!shouldRender) {
    return (
      <div className="flex items-center justify-center h-full min-h-[300px]">
        <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500 mr-3"></div>
        <span className="text-gray-500 dark:text-gray-300 text-lg">
          Rendering graph…
        </span>
      </div>
    );
  }
  return <>{children}</>;
}

export function Corrie() {
  const { data: services } = useGetServicesQuery();

  type FilterTags = { include: string[]; exclude: string[] };
  const [filterTags] = useSearchParam<FilterTags>(
    TAGS_FILTER_KEY,
    { include: [], exclude: [] },
    (value) =>
      value.include.length === 0 && value.exclude.length === 0
        ? null
        : JSON.stringify(value),
    (value) => JSON.parse(value) as FilterTags,
  );

  const [filterFlags] = useSearchParam<string[]>(
    FLAGS_FILTER_KEY,
    [],
    (value) => (value.length === 0 ? null : JSON.stringify(value)),
    (value) => JSON.parse(value) as string[],
  );
  const [filterFlagids] = useSearchParam<string[]>(
    FLAGIDS_FILTER_KEY,
    [],
    (value) => (value.length === 0 ? null : JSON.stringify(value)),
    (value) => JSON.parse(value) as string[],
  );

  const [searchParams, setSearchParams] = useSearchParams();

  const service_name = searchParams.get(SERVICE_FILTER_KEY) ?? "";
  const service = services && services.find((s) => s.name == service_name);

  const text_filter = searchParams.get(TEXT_FILTER_KEY) ?? undefined;
  const from_filter = searchParams.get(START_FILTER_KEY) ?? undefined;
  const to_filter = searchParams.get(END_FILTER_KEY) ?? undefined;

  // parse from_filter and to_filter as numbers
  const from_filter_num = from_filter ? parseInt(from_filter, 10) : undefined;
  const to_filter_num = to_filter ? parseInt(to_filter, 10) : undefined;

  const debounced_text_filter = useDebounce(text_filter, 300);

  const { data: flowData, isLoading } = useGetFlowsQuery(
    {
      "flow.data": debounced_text_filter,
      dst_ip: service?.ip,
      dst_port: service?.port,
      from_time: from_filter_num,
      to_time: to_filter_num,
      service: "", // FIXME
      includeTags: filterTags.include,
      excludeTags: filterTags.exclude,
      tags: filterTags.include,
      flags: filterFlags,
      flagids: filterFlagids,
    },
    {
      refetchOnMountOrArgChange: true,
      pollingInterval: FLOW_LIST_REFETCH_INTERVAL_MS,
    },
  );

  // TODO: fix the below transformation - move it to server
  // Diederik gives you a beer once it has been fixed
  const transformedFlowData = flowData?.data.map((flow) => ({
    ...flow,
    service_tag:
      services?.find((s) => s.ip === flow.dst_ip && s.port === flow.dst_port)
        ?.name ?? "unknown",
  }));

  const mode = searchParams.get("correlation") ?? "time";
  const setCorrelationMode = (mode: string) => {
    searchParams.set(CORRELATION_MODE_KEY, mode);
    setSearchParams(searchParams);
  };

  const inactiveButtonClass =
    "bg-blue-100 dark:bg-blue-900 text-gray-800 dark:text-gray-100 rounded-md px-2 py-1 border border-blue-200 dark:border-blue-800 cursor-pointer hover:bg-blue-200 dark:hover:bg-blue-800 transition-colors";
  const activeButtonClass = `${inactiveButtonClass} ring-2 ring-blue-400 dark:ring-blue-300`;

  const navigate = useNavigate();
  const onClickNavigate = useCallback(
    (loc: string) => navigate(loc, { replace: true }),
    [navigate],
  );

  const graphProps: GraphProps = {
    flowList: transformedFlowData || [],
    mode: mode,
    searchParams: searchParams,
    setSearchParams: setSearchParams,
    onClickNavigate: onClickNavigate,
  };

  return (
    <div className="flex flex-col h-full">
      <div className="text-sm bg-white dark:bg-gray-900 border-b-gray-300 dark:border-b-gray-700 border-b shadow-md flex flex-col">
        <div className="p-2 flex space-x-2" style={{ height: 50 }}>
          <a className="text-center px-2 py-2">Correlation mode: </a>
          <button
            type="button"
            className={mode == "time" ? activeButtonClass : inactiveButtonClass}
            onClick={() => setCorrelationMode("time")}
          >
            time
          </button>
          <button
            type="button"
            className={
              mode == "packets" ? activeButtonClass : inactiveButtonClass
            }
            onClick={() => setCorrelationMode("packets")}
          >
            packets
          </button>
          <button
            type="button"
            className={
              mode == "volume" ? activeButtonClass : inactiveButtonClass
            }
            onClick={() => setCorrelationMode("volume")}
          >
            volume
          </button>
        </div>
      </div>
      <div className="flex-1 w-full h-full overflow-hidden relative flex bg-white dark:bg-gray-900">
        {isLoading && (
          <div className="absolute inset-0 z-10 flex items-center justify-center bg-gray-100/80 dark:bg-gray-900/80">
            <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500 mr-3"></div>
            <span className="text-gray-500 dark:text-gray-300 text-lg">
              Loading graph…
            </span>
          </div>
        )}
        <div
          className={
            isLoading
              ? "opacity-50 pointer-events-none flex-1 h-full"
              : "flex-1 h-full"
          }
        >
          <DeferredChart
            key={
              mode +
              "-" +
              (graphProps.flowList.length ? graphProps.flowList[0]._id : "")
            }
          >
            {(mode == "packets" || mode == "time") &&
              TimePacketGraph(graphProps)}
            {mode == "volume" && VolumeGraph(graphProps)}
          </DeferredChart>
        </div>
      </div>
    </div>
  );
}

function TimePacketGraph(graphProps: GraphProps) {
  const flowList = graphProps.flowList;
  const mode = graphProps.mode;
  const searchParams = graphProps.searchParams;
  const setSearchParams = graphProps.setSearchParams;
  const onClickNavigate = graphProps.onClickNavigate;

  const series: ApexAxisChartSeries = [
    {
      name: "Flows",
      data: flowList.map((flow) => {
        let y = flow.duration;
        if (mode == "packets") {
          y = flow.num_packets;
        }
        return { x: flow.time, y: y };
      }),
    },
  ];

  const options: ApexOptions = {
    dataLabels: {
      enabled: false,
    },
    grid: {
      xaxis: {
        lines: {
          show: true,
        },
      },
      yaxis: {
        lines: {
          show: true,
        },
      },
    },
    xaxis: {
      type: "datetime", // FIXME: Timezone is not displayed correctly
    },
    labels: flowList.map((flow) => {
      return flow._id;
    }),
    chart: {
      animations: {
        enabled: false,
      },
      events: {
        dataPointSelection: (_event, _chartContext, config) => {
          // Retrieve flowList from chart's labels. This is hacky, refer to FIXME above.
          const flowIdList = config.w.config.labels;
          const flow = flowIdList[config.dataPointIndex];
          onClickNavigate(`/flow/${flow}?${searchParams}`);
        },
        beforeZoom: function (_chartContext, { xaxis }) {
          const start = Math.floor(xaxis.min);
          const end = Math.ceil(xaxis.max);
          searchParams.set(START_FILTER_KEY, start.toString());
          searchParams.set(END_FILTER_KEY, end.toString());
          setSearchParams(searchParams);
        },
      },
    },
  };

  return (
    <ReactApexChart
      options={options}
      series={series}
      type="scatter"
      width="100%"
      height="100%"
    />
  );
}

function VolumeGraph(graphProps: GraphProps) {
  const flowList = graphProps.flowList;
  const searchParams = graphProps.searchParams;
  const setSearchParams = graphProps.setSearchParams;

  function chunkData(flowList: Flow[]) {
    const ret: { x: number; y: number }[] = [];
    let ts = 0;
    let acc = 0;
    const window_size = 30000;
    flowList.forEach((flow) => {
      if (ts == 0) {
        ts = flow.time;
      }

      if (ts - flow.time > window_size) {
        ret.push({ x: ts, y: acc });
        ts = 0;
        acc = 0;
      } else {
        acc++;
      }
    });

    return ret;
  }

  const series_out: ApexAxisChartSeries = [
    {
      name: "Volume",
      data: chunkData(flowList),
    },
  ];

  const options: ApexOptions = {
    dataLabels: {
      enabled: false,
    },
    grid: {
      xaxis: {
        lines: {
          show: true,
        },
      },
      yaxis: {
        lines: {
          show: true,
        },
      },
    },
    xaxis: {
      type: "datetime", // FIXME: Timezone is not displayed correctly
    },
    labels: flowList.map((flow) => {
      return flow._id;
    }),
    chart: {
      animations: {
        enabled: false,
      },
      events: {
        beforeZoom: (_chartContext, { xaxis }) => {
          const start = Math.floor(xaxis.min);
          const end = Math.ceil(xaxis.max);
          searchParams.set(START_FILTER_KEY, start.toString());
          searchParams.set(END_FILTER_KEY, end.toString());
          setSearchParams(searchParams);
        },
      },
    },
  };

  return <ReactApexChart options={options} series={series_out} type="line" />;
}

export default Corrie;
