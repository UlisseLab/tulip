import { useState } from "react";
import { useSearchParams } from "react-router";
import { diffLines } from "diff";
import { hexy } from "hexy";

import type { FullFlow } from "../types";

import { RadioGroup } from "../components/RadioGroup";

import { FIRST_DIFF_KEY, SECOND_DIFF_KEY } from "../const";
import { useGetFlowQuery } from "../api";

type CustomDiffViewerProps = {
  oldValue: string;
  newValue: string;
  splitView?: boolean;
};

function DiffHeader({ splitView }: { splitView: boolean }) {
  return splitView ? (
    <div className="flex font-bold border-b border-gray-200 bg-gray-50 text-gray-700 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-200">
      <div className="w-12 px-2 py-1 text-right">Old</div>
      <div className="w-1/2 px-2 py-1 border-r border-gray-200 dark:border-gray-700">
        Original
      </div>
      <div className="w-12 px-2 py-1 text-right">New</div>
      <div className="w-1/2 px-2 py-1">Modified</div>
    </div>
  ) : (
    <div className="flex font-bold border-b border-gray-200 bg-gray-50 text-gray-700 dark:border-gray-700 dark:bg-gray-800 dark:text-gray-200">
      <div className="w-12 px-2 py-1 text-right">Line</div>
      <div className="flex-1 px-2 py-1">Diff</div>
    </div>
  );
}

function DiffRow({
  type,
  line,
  leftLine,
  rightLine,
  splitView,
}: {
  type: "unchanged" | "added" | "removed";
  line: string;
  leftLine?: number;
  rightLine?: number;
  splitView: boolean;
}) {
  if (splitView) {
    if (type === "unchanged") {
      return (
        <div className="flex border-b border-gray-100 bg-white dark:border-gray-800 dark:bg-gray-900">
          <div className="w-12 px-2 py-1 text-right text-gray-400">
            {leftLine}
          </div>
          <div className="w-1/2 px-2 py-1 border-r border-gray-100 dark:border-gray-800">
            {line}
          </div>
          <div className="w-12 px-2 py-1 text-right text-gray-400">
            {rightLine}
          </div>
          <div className="w-1/2 px-2 py-1">{line}</div>
        </div>
      );
    } else if (type === "added") {
      return (
        <div className="flex border-b border-gray-100 bg-green-100 dark:border-gray-800 dark:bg-green-900">
          <div className="w-12 px-2 py-1 text-right"></div>
          <div className="w-1/2 px-2 py-1 border-r border-gray-100 dark:border-gray-800"></div>
          <div className="w-12 px-2 py-1 text-right text-green-600 dark:text-green-300">
            {rightLine}
          </div>
          <div className="w-1/2 px-2 py-1">{line}</div>
        </div>
      );
    } else if (type === "removed") {
      return (
        <div className="flex border-b border-gray-100 bg-red-100 dark:border-gray-800 dark:bg-red-900">
          <div className="w-12 px-2 py-1 text-right text-red-600 dark:text-red-300">
            {leftLine}
          </div>
          <div className="w-1/2 px-2 py-1 border-r border-gray-100 dark:border-gray-800">
            {line}
          </div>
          <div className="w-12 px-2 py-1 text-right"></div>
          <div className="w-1/2 px-2 py-1"></div>
        </div>
      );
    }
  } else {
    if (type === "unchanged") {
      return (
        <div className="flex border-b border-gray-100 bg-white dark:border-gray-800 dark:bg-gray-900">
          <div className="w-12 px-2 py-1 text-right text-gray-400">
            {leftLine}
          </div>
          <div className="flex-1 px-2 py-1">{line}</div>
        </div>
      );
    } else if (type === "added") {
      return (
        <div className="flex border-b border-gray-100 bg-green-100 dark:border-gray-800 dark:bg-green-900">
          <div className="w-12 px-2 py-1 text-right text-green-600 dark:text-green-300">
            {rightLine}
          </div>
          <div className="flex-1 px-2 py-1">{line}</div>
        </div>
      );
    } else if (type === "removed") {
      return (
        <div className="flex border-b border-gray-100 bg-red-100 dark:border-gray-800 dark:bg-red-900">
          <div className="w-12 px-2 py-1 text-right text-red-600 dark:text-red-300">
            {leftLine}
          </div>
          <div className="flex-1 px-2 py-1">{line}</div>
        </div>
      );
    }
  }
  return null;
}

function CustomDiffViewer({
  oldValue,
  newValue,
  splitView = true,
}: CustomDiffViewerProps) {
  const lineDiff = diffLines(oldValue, newValue);

  let leftLine = 1;
  let rightLine = 1;

  return (
    <div className="w-full text-sm font-mono border rounded bg-white text-gray-800 border-gray-300 dark:bg-gray-900 dark:text-gray-100 dark:border-gray-700">
      <DiffHeader splitView={splitView} />
      <div className="flex flex-col">
        {lineDiff.map((part) => {
          const lines = part.value.split("\n");
          if (lines[lines.length - 1] === "") lines.pop();

          if (!part.added && !part.removed) {
            return lines.map((line) => {
              const row = (
                <DiffRow
                  type="unchanged"
                  line={line}
                  leftLine={leftLine}
                  rightLine={rightLine}
                  splitView={splitView}
                />
              );
              leftLine++;
              rightLine++;
              return row;
            });
          } else if (part.added) {
            return lines.map((line) => {
              const row = (
                <DiffRow
                  type="added"
                  line={line}
                  rightLine={rightLine}
                  splitView={splitView}
                />
              );
              rightLine++;
              return row;
            });
          } else if (part.removed) {
            return lines.map((line) => {
              const row = (
                <DiffRow
                  type="removed"
                  line={line}
                  leftLine={leftLine}
                  splitView={splitView}
                />
              );
              leftLine++;
              return row;
            });
          } else {
            return null;
          }
        })}
      </div>
    </div>
  );
}

function Flow(flow1: string, flow2: string, splitView: boolean) {
  return (
    <div>
      <CustomDiffViewer
        oldValue={flow1}
        newValue={flow2}
        splitView={splitView}
      />
      <hr
        style={{
          height: "1px",
          color: "inherit",
          borderTopWidth: "5px",
        }}
      />
    </div>
  );
}

function isASCII(str: string) {
  return Array.from(str).every((ch) => ch.charCodeAt(0) <= 127);
}

const displayOptions = ["Plain", "Hex"] as const;
type DisplayOption = (typeof displayOptions)[number];

// Derives the display mode for two given flows
const deriveDisplayMode = (
  firstFlow: FullFlow,
  secondFlow: FullFlow,
): DisplayOption => {
  if (firstFlow && secondFlow) {
    for (
      let i = 0;
      i < Math.min(firstFlow.flow.length, secondFlow.flow.length);
      i++
    ) {
      if (
        !isASCII(firstFlow.flow[i].data) ||
        !isASCII(secondFlow.flow[i].data)
      ) {
        return displayOptions[1];
      }
    }
  }

  return displayOptions[0];
};

export function DiffView() {
  const [searchParams] = useSearchParams();
  const firstFlowId = searchParams.get(FIRST_DIFF_KEY);
  const secondFlowId = searchParams.get(SECOND_DIFF_KEY);

  // If either flow id is not provided, we skip the query
  if (firstFlowId === null || secondFlowId === null) {
    return (
      <div className="flex justify-center items-center h-full">
        <div>
          <p className="text-red-500 text-lg font-semibold mb-2">
            Error: Missing Flow IDs
          </p>
          <p className="text-gray-500 mb-4">
            Please ensure that both flow IDs are provided in the URL query
            parameters.
          </p>
          <p className="text-gray-500 mb-4">
            Example:{" "}
            <code>
              ?{FIRST_DIFF_KEY}=flow1Id&{SECOND_DIFF_KEY}=flow2Id
            </code>
          </p>
          <p className="text-gray-500 mb-4">
            If you are trying to compare flows, please select two flows from the
            sidebar using <kbd>f</kbd> and <kbd>g</kbd> keys.
          </p>
        </div>
      </div>
    );
  }

  const { data: firstFlow, isLoading: firstFlowLoading } = useGetFlowQuery(
    firstFlowId!,
    {
      skip: firstFlowId === null,
    },
  );

  const { data: secondFlow, isLoading: secondFlowLoading } = useGetFlowQuery(
    secondFlowId!,
    {
      skip: secondFlowId === null,
    },
  );

  const [displayOption, setDisplayOption] = useState(() =>
    deriveDisplayMode(firstFlow!, secondFlow!),
  );
  const [splitView, setSplitView] = useState(true);

  if (firstFlowId === null || secondFlowId === null) {
    return <div>Invalid flow id</div>;
  }

  if (firstFlowLoading || secondFlowLoading) {
    return <div>Loading...</div>;
  }

  return (
    <div className="bg-white dark:bg-gray-900 text-gray-800 dark:text-gray-100 min-h-screen">
      <div className="sticky shadow-md bg-white dark:bg-gray-900 overflow-auto py-1 border-y border-gray-300 dark:border-gray-700 flex items-center gap-2 px-4">
        <RadioGroup
          options={displayOptions}
          value={displayOption}
          onChange={setDisplayOption}
          className="flex gap-2 text-gray-800 dark:text-gray-100 text-sm mr-4"
        />
        <button
          type="button"
          className={`px-3 py-1 rounded-md border text-sm transition-colors cursor-pointer ${
            splitView
              ? "bg-blue-500 text-white border-blue-600"
              : "bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-100 border-gray-300 dark:border-gray-700 hover:bg-blue-200 dark:hover:bg-blue-900"
          }`}
          onClick={() => setSplitView(true)}
        >
          Split
        </button>
        <button
          type="button"
          className={`px-3 py-1 rounded-md border text-sm transition-colors cursor-pointer ${
            !splitView
              ? "bg-blue-500 text-white border-blue-600"
              : "bg-gray-100 dark:bg-gray-800 text-gray-800 dark:text-gray-100 border-gray-300 dark:border-gray-700 hover:bg-blue-200 dark:hover:bg-blue-900"
          }`}
          onClick={() => setSplitView(false)}
        >
          Inline
        </button>
      </div>

      {/* Plain */}
      {displayOption === "Plain" && (
        <div className="bg-white dark:bg-gray-900 text-gray-800 dark:text-gray-100 min-h-screen">
          {Array.from(
            {
              length: Math.min(firstFlow!.flow.length, secondFlow!.flow.length),
            },
            (_, i) =>
              Flow(
                firstFlow!.flow[i].data,
                secondFlow!.flow[i].data,
                splitView,
              ),
          )}
        </div>
      )}

      {/* Hex */}
      {displayOption === "Hex" && (
        <div className="bg-white dark:bg-gray-900 text-gray-800 dark:text-gray-100 min-h-screen">
          {Array.from(
            {
              length: Math.min(firstFlow!.flow.length, secondFlow!.flow.length),
            },
            (_, i) =>
              Flow(
                hexy(firstFlow!.flow[i].data, { format: "twos" }),
                hexy(secondFlow!.flow[i].data, { format: "twos" }),
                splitView,
              ),
          )}
        </div>
      )}
    </div>
  );
}

export default DiffView;
