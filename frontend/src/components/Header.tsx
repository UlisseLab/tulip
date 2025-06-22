import { Suspense } from "react";
import { useHotkeys } from "react-hotkeys-hook";
import { Link, useParams, useSearchParams, useNavigate } from "react-router";

import {
  END_FILTER_KEY,
  SERVICE_FILTER_KEY,
  START_FILTER_KEY,
  TEXT_FILTER_KEY,
  FIRST_DIFF_KEY,
  SECOND_DIFF_KEY,
  SERVICE_REFETCH_INTERVAL_MS,
  TICK_REFETCH_INTERVAL_MS,
} from "../const";

import { useGetServicesQuery, useGetTickInfoQuery } from "../api";

function ServiceSelection() {
  const FILTER_KEY = SERVICE_FILTER_KEY;

  const { data: services } = useGetServicesQuery(undefined, {
    pollingInterval: SERVICE_REFETCH_INTERVAL_MS,
  });

  const servicesList: Service[] = [
    { ip: "", port: 0, name: "all" },
    ...(services || []),
  ];

  const [service, setService] = useSearchParam<string>(
    FILTER_KEY,
    "all",
    (value) => (value === "all" ? null : value),
    (value) => (value === null ? "all" : value),
  );

  const onChangeService = (event: React.ChangeEvent<HTMLSelectElement>) => {
    const selectedService = event.target.value;
    setService(selectedService);
  };

  return (
    <select
      className="w-20 border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-100 px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-400 dark:focus:ring-blue-300 transition-colors"
      title="Service"
      value={service}
      onChange={onChangeService}
    >
      {servicesList.map((service) => (
        <option
          key={service.name}
          value={service.name}
          className="bg-white dark:bg-gray-800 text-gray-800 dark:text-gray-100"
        >
          {service.name}
        </option>
      ))}
    </select>
  );
}

function TextSearch() {
  const FILTER_KEY = TEXT_FILTER_KEY;
  const [searchParams, setSearchParams] = useSearchParams();

  useHotkeys("s", (e) => {
    const el = document.getElementById("search") as HTMLInputElement;
    el?.focus();
    el?.select();
    e.preventDefault();
  });

  return (
    <div>
      <input
        type="text"
        placeholder="regex"
        id="search"
        value={searchParams.get(FILTER_KEY) || ""}
        onChange={(event) => {
          const textFilter = event.target.value;
          if (textFilter != null && textFilter !== "") {
            searchParams.set(FILTER_KEY, textFilter);
          } else {
            searchParams.delete(FILTER_KEY);
          }
          setSearchParams(searchParams);
        }}
        className="w-full border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-100 px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-400 dark:focus:ring-blue-300 transition-colors"
      />
    </div>
  );
}

function useMessyTimeStuff() {
  const [searchParams, setSearchParams] = useSearchParams();

  const { data: tickInfoData } = useGetTickInfoQuery(undefined, {
    pollingInterval: TICK_REFETCH_INTERVAL_MS,
  });

  // TODO: prevent having to work with default values here
  let startDate = "1970-01-01T00:00:00Z";
  let tickLength = 1000;

  if (tickInfoData) {
    startDate = tickInfoData.startDate;
    tickLength = tickInfoData.tickLength;
  }

  function setTimeParam(startTick: string, param: string) {
    const parsedTick = startTick === "" ? undefined : parseInt(startTick);
    const unixTime = tickToUnixTime(parsedTick);
    if (unixTime) {
      searchParams.set(param, unixTime.toString());
    } else {
      searchParams.delete(param);
    }
    setSearchParams(searchParams);
  }

  const startTimeParamUnix = searchParams.get(START_FILTER_KEY);
  const endTimeParamUnix = searchParams.get(END_FILTER_KEY);

  function unixTimeToTick(unixTime: string | null): number | undefined {
    if (unixTime === null) {
      return;
    }
    const unixTimeInt = parseInt(unixTime);
    if (isNaN(unixTimeInt)) {
      return;
    }
    const tick = Math.floor(
      (unixTimeInt - new Date(startDate).valueOf()) / tickLength,
    );

    return tick;
  }

  function tickToUnixTime(tick?: number) {
    if (!tick) {
      return;
    }
    const unixTime = new Date(startDate).valueOf() + tickLength * tick;
    return unixTime;
  }

  const startTick = unixTimeToTick(startTimeParamUnix);
  const endTick = unixTimeToTick(endTimeParamUnix);
  const currentTick = unixTimeToTick(new Date().valueOf().toString());

  function setToLastnTicks(n: number) {
    const startTick = (currentTick ?? 0) - n;
    const endTick = (currentTick ?? 0) + 1; // to be sure
    setTimeParam(startTick.toString(), START_FILTER_KEY);
    setTimeParam(endTick.toString(), END_FILTER_KEY);
  }

  return {
    unixTimeToTick,
    startDate,
    tickLength,
    setTimeParam,
    startTick,
    endTick,
    currentTick,
    setToLastnTicks,
  };
}

function StartDateSelection() {
  const { setTimeParam, startTick } = useMessyTimeStuff();

  return (
    <div>
      <input
        className="w-20 border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-100 px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-400 dark:focus:ring-blue-300 transition-colors"
        id="startdateselection"
        type="number"
        placeholder="from"
        value={startTick}
        onChange={(event) => {
          setTimeParam(event.target.value, START_FILTER_KEY);
        }}
      />
    </div>
  );
}

function EndDateSelection() {
  const { setTimeParam, endTick } = useMessyTimeStuff();

  return (
    <div>
      <input
        className="w-20 border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-100 px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-400 dark:focus:ring-blue-300 transition-colors"
        id="enddateselection"
        type="number"
        placeholder="to"
        value={endTick}
        onChange={(event) => {
          setTimeParam(event.target.value, END_FILTER_KEY);
        }}
      />
    </div>
  );
}

function FirstDiff() {
  const { id } = useParams();

  const [firstDiffFlow, setFirstDiffFlow] = useSearchParam<string>(
    FIRST_DIFF_KEY,
    "",
    (value) => (value === "" ? null : value),
    (value) => (value === null ? "" : value),
  );

  useHotkeys("f", () => {
    if (id) {
      setFirstDiffFlow(id);
    } else {
      setFirstDiffFlow("");
    }
  });

  return (
    <input
      type="text"
      className="md:w-72 cursor-pointer border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-100 px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-400 dark:focus:ring-blue-300 transition-colors"
      placeholder="First Diff ID"
      readOnly
      value={firstDiffFlow}
      title="Click to set first diff flow, right click to clear"
      onClick={() => setFirstDiffFlow(id ?? null)}
      onContextMenu={(event) => {
        event.preventDefault();
        setFirstDiffFlow(null);
      }}
    />
  );
}

function SecondDiff() {
  const { id } = useParams();

  const [secondDiffFlow, setSecondDiffFlow] = useSearchParam<string>(
    SECOND_DIFF_KEY,
    "",
    (value) => (value === "" ? null : value),
    (value) => (value === null ? "" : value),
  );

  useHotkeys("g", () => {
    setSecondDiffFlow(id ?? "");
  });

  return (
    <input
      type="text"
      className="md:w-72 cursor-pointer border border-gray-300 dark:border-gray-700 rounded-md bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-100 px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-400 dark:focus:ring-blue-300 transition-colors"
      placeholder="Second Flow ID"
      title="Click to set second diff flow, right click to clear"
      readOnly
      value={secondDiffFlow}
      onClick={() => setSecondDiffFlow(id ?? null)}
      onContextMenu={(e) => {
        e.preventDefault();
        setSecondDiffFlow(null);
      }}
    />
  );
}

function Diff() {
  const params = useParams();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  const navigateToDiff = () =>
    navigate(`/diff/${params.id ?? ""}?${searchParams}`, { replace: true });

  useHotkeys("d", navigateToDiff);

  return (
    <button
      type="button"
      className="bg-amber-100 dark:bg-amber-900 text-gray-800 dark:text-gray-100 rounded-md border border-amber-300 dark:border-amber-800 px-2 py-1 cursor-pointer hover:bg-amber-200 dark:hover:bg-amber-800 transition-colors"
      onClick={navigateToDiff}
    >
      Diff
    </button>
  );
}

import { useSearchParam } from "../store/param";
import type { Service } from "../types";

export function Header() {
  const [searchParams] = useSearchParams();
  const { setToLastnTicks, currentTick, setTimeParam } = useMessyTimeStuff();

  useHotkeys("a", () => setToLastnTicks(5));
  useHotkeys("c", () => {
    (document.getElementById("startdateselection") as HTMLInputElement).value =
      "";
    (document.getElementById("enddateselection") as HTMLInputElement).value =
      "";
    setTimeParam("", START_FILTER_KEY);
    setTimeParam("", END_FILTER_KEY);
  });

  return (
    <>
      <Link to={`/?${searchParams}`}>
        <div className="header-icon">🌷</div>
      </Link>
      <div>
        <TextSearch></TextSearch>
      </div>
      <div>
        <Suspense>
          <ServiceSelection></ServiceSelection>
        </Suspense>
      </div>
      <div>
        <StartDateSelection></StartDateSelection>
      </div>
      <div>
        <EndDateSelection></EndDateSelection>
      </div>
      <div>
        <button
          type="button"
          className="bg-amber-100 dark:bg-amber-900 text-gray-800 dark:text-gray-100 rounded-md border border-amber-300 dark:border-amber-800 px-2 py-1 text-center cursor-pointer hover:bg-amber-200 dark:hover:bg-amber-800 transition-colors"
          onClick={() => setToLastnTicks(5)}
        >
          Last 5 ticks
        </button>
      </div>
      <Link to={`/corrie?${searchParams}`}>
        <div className="bg-blue-100 dark:bg-blue-900 text-gray-800 dark:text-gray-100 rounded-md border border-blue-300 dark:border-blue-800 px-2 py-1 text-center hover:bg-blue-200 dark:hover:bg-blue-800 cursor-pointer transition-colors">
          Graph view
        </div>
      </Link>

      <div className="ml-auto mr-4 flex items-center">
        <div className="mr-4">
          <FirstDiff />
        </div>
        <div className="mr-4">
          <SecondDiff />
        </div>
        <div className="mr-6">
          <Suspense>
            <Diff />
          </Suspense>
        </div>
        <div className="ml-auto flex justify-center items-center flex-col">
          <span className="inline-block bg-blue-100 dark:bg-blue-800 text-blue-800 dark:text-blue-100 text-xs font-semibold px-3 py-1 rounded-full border border-blue-300 dark:border-blue-700">
            Tick: {currentTick}
          </span>
        </div>
      </div>
    </>
  );
}
