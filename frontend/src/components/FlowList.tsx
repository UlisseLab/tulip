import { useSearchParams, Link, useParams, useNavigate } from "react-router";
import { useState, useRef, useEffect } from "react";
import { useHotkeys } from "react-hotkeys-hook";
import type { Flow } from "../types";
import {
  SERVICE_FILTER_KEY,
  TEXT_FILTER_KEY,
  START_FILTER_KEY,
  END_FILTER_KEY,
  FLOW_LIST_REFETCH_INTERVAL_MS,
} from "../const";
import { useAppSelector, useAppDispatch } from "../store";
import { toggleFilterTag } from "../store/filter";

import {
  HeartIcon,
  AdjustmentsHorizontalIcon,
  LinkIcon,
} from "@heroicons/react/20/solid";
import { HeartIcon as EmptyHeartIcon } from "@heroicons/react/24/outline";

import { format } from "date-fns";
import useDebounce from "../hooks/useDebounce";
import { Virtuoso, type VirtuosoHandle } from "react-virtuoso";
import classNames from "classnames";
import { Tag } from "./Tag";
import {
  useGetFlowsQuery,
  useGetServicesQuery,
  useGetTagsQuery,
  useStarFlowMutation,
} from "../api";
import { useSearchParam } from "../store/param";

export function FlowList() {
  const [searchParams] = useSearchParams();
  const params = useParams();

  // we add a local variable to prevent racing with the browser location API
  let openedFlowID = params.id;

  const { data: availableTags } = useGetTagsQuery();
  const { data: services } = useGetServicesQuery();

  const filterFlags = useAppSelector((state) => state.filter.filterFlags);
  const filterFlagids = useAppSelector((state) => state.filter.filterFlagids);

  type FilterTags = {
    include: string[];
    exclude: string[];
  };

  const [filterTags, setFilterTags] = useSearchParam<FilterTags>(
    "tags",
    { include: [], exclude: [] },
    (value) => {
      if (value.include.length === 0 && value.exclude.length === 0) {
        return null; // if both include and exclude are empty, we don't want to set the search param
      }
      return JSON.stringify(value);
    },
    (value) => JSON.parse(value) as FilterTags,
  );

  const onTagClick = (tag: string) => {
    // if the tag is already included, we want to exclude it
    if (filterTags.include.includes(tag)) {
      setFilterTags({
        include: filterTags.include.filter((t) => t !== tag),
        exclude: [...filterTags.exclude, tag],
      });
    } else if (filterTags.exclude.includes(tag)) {
      // if the tag is already excluded, we want to remove it from both include and exclude
      setFilterTags({
        include: filterTags.include.filter((t) => t !== tag),
        exclude: filterTags.exclude.filter((t) => t !== tag),
      });
    } else {
      // if the tag is not included or excluded, we want to include it
      setFilterTags({
        include: [...filterTags.include, tag],
        exclude: filterTags.exclude.filter((t) => t !== tag),
      });
    }
  };

  const dispatch = useAppDispatch();

  const [starFlow] = useStarFlowMutation();

  const [flowIndex, setFlowIndex] = useState<number>(0);

  const virtuoso = useRef<VirtuosoHandle>(null);

  const [serviceName] = useSearchParam<string>(
    SERVICE_FILTER_KEY,
    "",
    (value) => value,
    (value) => value,
  );

  const service = services?.find((s) => s.name == serviceName);

  const text_filter = searchParams.get(TEXT_FILTER_KEY) ?? undefined;
  const from_filter = searchParams.get(START_FILTER_KEY) ?? undefined;
  const to_filter = searchParams.get(END_FILTER_KEY) ?? undefined;

  // parse from_filter and to_filter as numbers
  const from_filter_num = from_filter ? parseInt(from_filter, 10) : undefined;
  const to_filter_num = to_filter ? parseInt(to_filter, 10) : undefined;

  const debounced_text_filter = useDebounce(text_filter, 300);

  const {
    data: flowData,
    isLoading,
    refetch,
  } = useGetFlowsQuery(
    {
      "flow.data": debounced_text_filter,
      dst_ip: service?.ip,
      dst_port: service?.port,
      from_time: from_filter_num,
      to_time: to_filter_num,
      service: service?.name ?? "",
      tags: filterTags.include,
      flags: filterFlags,
      flagids: filterFlagids,
      includeTags: filterTags.include,
      excludeTags: filterTags.exclude,
    },
    {
      refetchOnMountOrArgChange: true,
      pollingInterval: FLOW_LIST_REFETCH_INTERVAL_MS,
    },
  );

  // TODO: fix the below transformation - move it to server
  // Diederik gives you a beer once it has been fixed
  const transformedFlowData = flowData?.map((flow) => ({
    ...flow,
    service_tag:
      services?.find((s) => s.ip === flow.dst_ip && s.port === flow.dst_port)
        ?.name ?? "unknown",
  }));

  const onHeartHandler = async (flow: Flow) => {
    await starFlow({ id: flow._id, star: !flow.tags.includes("starred") });
  };

  const navigate = useNavigate();

  useEffect(() => {
    virtuoso?.current?.scrollIntoView({
      index: flowIndex,
      behavior: "auto",
      done: () => {
        if (transformedFlowData && transformedFlowData[flowIndex ?? 0]) {
          const idAtIndex = transformedFlowData[flowIndex ?? 0]._id;
          // if the current flow ID at the index indeed did change (ie because of keyboard navigation), we need to update the URL as well as local ID
          if (idAtIndex !== openedFlowID) {
            navigate(`/flow/${idAtIndex}?${searchParams}`);
            openedFlowID = idAtIndex;
          }
        }
      },
    });
  }, [flowIndex]);

  // TODO: there must be a better way to do this
  // this gets called on every refetch, we dont want to iterate all flows on every refetch
  // so because performance, we hack this by checking if the transformedFlowData length changed
  const [transformedFlowDataLength, setTransformedFlowDataLength] =
    useState<number>(0);

  useEffect(() => {
    if (
      transformedFlowData &&
      transformedFlowDataLength != transformedFlowData?.length
    ) {
      setTransformedFlowDataLength(transformedFlowData?.length);

      for (let i = 0; i < transformedFlowData?.length; i++) {
        if (transformedFlowData[i]._id === openedFlowID) {
          if (i !== flowIndex) {
            setFlowIndex(i);
          }
          return;
        }
      }
      setFlowIndex(0);
    }
  }, [transformedFlowData]);

  useHotkeys(
    "j",
    () =>
      setFlowIndex((fi) =>
        Math.min((transformedFlowData?.length ?? 1) - 1, fi + 1),
      ),
    [transformedFlowData?.length],
  );

  useHotkeys("k", () => setFlowIndex((fi) => Math.max(0, fi - 1)));

  useHotkeys(
    "i",
    () => {
      setShowFilters(true);
      if ((availableTags ?? []).includes("flag-in")) {
        dispatch(toggleFilterTag("flag-in"));
      }
    },
    [availableTags],
  );

  useHotkeys(
    "o",
    () => {
      setShowFilters(true);
      if ((availableTags ?? []).includes("flag-out")) {
        dispatch(toggleFilterTag("flag-out"));
      }
    },
    [availableTags],
  );
  useHotkeys("r", () => refetch());

  const [showFilters, setShowFilters] = useState(false);
  const [manualLoading, setManualLoading] = useState(false);

  // Wrap refetch to show loading indicator immediately
  const handleManualRefresh = async () => {
    setManualLoading(true);
    try {
      await refetch();
    } finally {
      setManualLoading(false);
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div
        className={classNames(
          "border-b shadow-md flex flex-col",
          "bg-white border-b-gray-300 text-gray-700",
          "dark:bg-gray-800 dark:text-white dark:border-gray-700",
        )}
      >
        <div className="flex flex-row items-center p-0 m-0 w-full">
          <div className="flex w-full h-10">
            <button
              type="button"
              className={classNames(
                "flex-1 border border-gray-300 dark:border-gray-700 text-sm transition-colors cursor-pointer",
                "bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-100 hover:bg-blue-200 dark:hover:bg-blue-900 flex items-center justify-center gap-2",
                { "opacity-70": manualLoading },
              )}
              onClick={handleManualRefresh}
              title="Refresh flows"
              disabled={manualLoading}
              style={{ margin: 0, borderRight: "none" }}
            >
              {manualLoading ? (
                <span className="animate-spin rounded-full h-4 w-4 border-t-2 border-b-2 border-blue-500"></span>
              ) : null}
              Refresh
            </button>
            <button
              type="button"
              className={classNames(
                "flex-1 border border-gray-300 dark:border-gray-700 text-sm transition-colors cursor-pointer",
                "bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-100 hover:bg-blue-200 dark:hover:bg-blue-900 flex items-center justify-center gap-2",
              )}
              onClick={() => setShowFilters(!showFilters)}
            >
              <AdjustmentsHorizontalIcon
                height={20}
                className="text-gray-400 dark:text-gray-300"
              />
              {showFilters ? "Close" : "Open"} filters
            </button>
          </div>
        </div>

        {showFilters && (
          <div className="border-t-gray-300 dark:border-t-gray-700 border-t p-2 transition-all duration-300">
            <p className="text-sm font-bold text-gray-600 pb-2 dark:text-gray-300">
              Intersection filter
            </p>
            <div className="flex gap-2 flex-wrap">
              {(availableTags ?? []).map((tag) => (
                <Tag
                  key={tag}
                  tag={tag}
                  disabled={
                    !filterTags.include.includes(tag) &&
                    !filterTags.exclude.includes(tag)
                  }
                  excluded={filterTags.exclude.includes(tag)}
                  onClick={() => onTagClick(tag)}
                />
              ))}
            </div>
          </div>
        )}
      </div>
      <div></div>
      {isLoading && !manualLoading ? (
        <div className="flex flex-1 items-center justify-center py-8">
          <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500 mr-3"></div>
          <span className="text-gray-500 dark:text-gray-300 text-lg">
            Loading flows…
          </span>
        </div>
      ) : (
        <div className="relative flex-1 flex flex-col">
          {manualLoading && (
            <div className="absolute inset-0 z-10 flex items-center justify-center bg-gray-100/80 dark:bg-gray-900/80">
              <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-blue-500 mr-3"></div>
              <span className="text-gray-500 dark:text-gray-300 text-lg">
                Refreshing…
              </span>
            </div>
          )}
          <Virtuoso
            className={classNames(["flex", "flex-col", "flex-1"], {
              "sidebar-loading": isLoading,
            })}
            data={transformedFlowData}
            ref={virtuoso}
            initialTopMostItemIndex={flowIndex}
            itemContent={(index, flow) => (
              <Link
                to={`/flow/${flow._id}?${searchParams}`}
                onClick={() => setFlowIndex(index)}
                key={flow._id}
              >
                <FlowListEntry
                  key={flow._id}
                  flow={flow}
                  isActive={flow._id === openedFlowID}
                  onHeartClick={onHeartHandler}
                />
              </Link>
            )}
          />
        </div>
      )}
    </div>
  );
}

interface FlowListEntryProps {
  flow: Flow;
  isActive: boolean;
  onHeartClick: (flow: Flow) => void;
}

function FlowListEntry({ flow, isActive, onHeartClick }: FlowListEntryProps) {
  const formatted_time_h_m_s = format(new Date(flow.time), "HH:mm:ss");
  const formatted_time_ms = format(new Date(flow.time), ".SSS");

  const isStarred = flow.tags.includes("starred");
  // Filter tag list for tags that are handled specially
  const filteredTagList = flow.tags.filter((t) => t != "starred");

  return (
    <li
      className={classNames({
        "bg-gray-100 dark:bg-gray-800 p-2 focus:ring-4 border-t border-gray-200 dark:border-gray-700 list-none":
          true,
        "border-y border-l-4 border-gray-500 dark:border-gray-400 bg-gray-300/50 dark:bg-gray-700/50":
          isActive,
      })}
    >
      <div className="flex">
        <div
          className="w-5 ml-1 mr-1 self-center shrink-0"
          onClick={() => {
            onHeartClick(flow);
          }}
        >
          {isStarred ? (
            <HeartIcon className="text-red-500 dark:text-red-400" />
          ) : (
            <EmptyHeartIcon className="dark:text-gray-300" />
          )}
        </div>

        <div className="w-5 mr-2 self-center shrink-0">
          {flow.child_id != "000000000000000000000000" ||
          flow.parent_id != "000000000000000000000000" ? (
            <LinkIcon className="text-blue-500 dark:text-blue-400" />
          ) : undefined}
        </div>
        <div className="flex-1 shrink ">
          <div className="flex">
            <div className="shrink-0">
              →{" "}
              <span className="text-gray-700 dark:text-gray-100 font-bold text-ellipsis overflow-hidden">
                {flow.service_tag}
              </span>
              <span className="text-gray-500 dark:text-gray-400">
                {" "}
                (:{flow.dst_port})
              </span>
            </div>

            <div className="ml-2">
              <span className="text-gray-500 dark:text-gray-400">
                {formatted_time_h_m_s}
              </span>
              <span className="text-gray-300 dark:text-gray-500">
                {formatted_time_ms}
              </span>
            </div>
            <div className="text-gray-500 dark:text-gray-400 ml-auto text-sm">
              {flow.duration > 10000 ? (
                <div className="text-red-500 dark:text-red-400">&gt;10s</div>
              ) : (
                <div>{flow.duration}ms</div>
              )}
            </div>
          </div>

          <hr className="border-gray-200 dark:border-gray-700 my-2" />
          <div className="flex gap-2 flex-wrap">
            {filteredTagList.map((tag) => (
              <Tag key={tag} tag={tag}></Tag>
            ))}
          </div>
        </div>
      </div>
    </li>
  );
}

export { FlowListEntry };
