import { useSearchParams } from "react-router";
import { useState } from "react";

import type { FullFlow } from "../types";

import ReactDiffViewer from "react-diff-viewer";
import { RadioGroup } from "../components/RadioGroup";

import { hexy } from "hexy";

import { FIRST_DIFF_KEY, SECOND_DIFF_KEY } from "../const";
import { useGetFlowQuery } from "../api";

function Flow(flow1: string, flow2: string) {
  return (
    <div>
      <ReactDiffViewer
        oldValue={flow1}
        newValue={flow2}
        splitView={true}
        showDiffOnly={false}
        useDarkTheme={false}
        hideLineNumbers={true}
        styles={{
          line: {
            wordBreak: "break-word",
          },
        }}
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

const displayOptions = ["Plain", "Hex"];

// Derives the display mode for two given flows
const deriveDisplayMode = (
  firstFlow: FullFlow,
  secondFlow: FullFlow
): (typeof displayOptions)[number] => {
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
    }
  );

  const { data: secondFlow, isLoading: secondFlowLoading } = useGetFlowQuery(
    secondFlowId!,
    {
      skip: secondFlowId === null,
    }
  );

  const [displayOption, setDisplayOption] = useState(
    deriveDisplayMode(firstFlow!, secondFlow!)
  );

  if (firstFlowId === null || secondFlowId === null) {
    return <div>Invalid flow id</div>;
  }

  if (firstFlowLoading || secondFlowLoading) {
    return <div>Loading...</div>;
  }

  return (
    <div>
      <div className="sticky shadow-md bg-white overflow-auto py-1 border-y flex items-center">
        <RadioGroup
          options={displayOptions}
          value={displayOption}
          onChange={setDisplayOption}
          className="flex gap-2 text-gray-800 text-sm mr-4"
        />
      </div>

      {/* Plain */}
      {displayOption === displayOptions[0] && (
        <div>
          {Array.from(
            {
              length: Math.min(firstFlow!.flow.length, secondFlow!.flow.length),
            },
            (_, i) => Flow(firstFlow!.flow[i].data, secondFlow!.flow[i].data)
          )}
        </div>
      )}

      {/* Hex */}
      {displayOption === displayOptions[1] && (
        <div>
          {Array.from(
            {
              length: Math.min(firstFlow!.flow.length, secondFlow!.flow.length),
            },
            (_, i) =>
              Flow(
                hexy(firstFlow!.flow[i].data, { format: "twos" }),
                hexy(secondFlow!.flow[i].data, { format: "twos" })
              )
          )}
        </div>
      )}
    </div>
  );
}

export default DiffView;
