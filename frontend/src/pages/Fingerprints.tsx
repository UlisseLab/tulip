import { Virtuoso } from "react-virtuoso";
import { useGetFingerprintsQuery, useGetFlowsQuery } from "../api";
import { Link } from "react-router";

export function Fingerprints() {
  const { data: fingerprints, isLoading } = useGetFingerprintsQuery();
  // Import Virtuoso at the top of your file:
  // import { Virtuoso } from 'react-virtuoso';

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-[60vh]">
        <span className="text-4xl font-bold">Loading...</span>
      </div>
    );
  }

  if (!fingerprints || fingerprints.length === 0) {
    return (
      <div className="text-center text-gray-500 dark:text-gray-400 text-lg mt-10">
        No fingerprints found.
      </div>
    );
  }

  return (
    <div className="mx-8 mt-10 h-full">
      <h2 className="text-3xl font-bold mb-6 text-center">Fingerprints</h2>
      {fingerprints.length > 0 ? (
        <Virtuoso
          data={fingerprints}
          itemContent={(index, fingerprint) => (
            <div className="mb-4">
              <FingerprintSection key={fingerprint} fingerprint={fingerprint} />
            </div>
          )}
        />
      ) : (
        <div className="text-center text-gray-500 dark:text-gray-400 text-lg">
          No fingerprints found.
        </div>
      )}
    </div>
  );
}

function FingerprintSection({ fingerprint }: { fingerprint: number }) {
  const { data: flows, isLoading } = useGetFlowsQuery({
    fingerprints: [fingerprint],
  });

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-[60vh]">
        <span className="text-2xl font-bold">Loading flows...</span>
      </div>
    );
  }

  if (!flows || !flows.data || flows.data.length === 0) {
    return (
      <section
        key={fingerprint}
        className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg shadow p-5"
      >
        <div className="text-center text-gray-500 dark:text-gray-400">
          No flows found for fingerprint {fingerprint}.
        </div>
      </section>
    );
  }

  return (
    <section
      key={fingerprint}
      className="bg-white dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg shadow p-5 flex flex-col"
    >
      <div className="mb-2 flex items-center justify-between">
        <span className="font-mono text-blue-700 dark:text-blue-300 break-all text-sm">
          {fingerprint}
        </span>
        <span className="ml-2 bg-blue-100 dark:bg-blue-900 dark:text-blue-200 text-blue-800 text-xs font-semibold px-2.5 py-0.5 rounded">
          {flows.data.length} flow{flows.data.length !== 1 ? "s" : ""}
        </span>
      </div>
      <div>
        <ul className="space-y-1">
          {flows.data.slice(0, 5).map((flow, idx: number) => (
            <li key={flow._id || idx}>
              Flow
              <Link
                to={flow._id ? `/flow/${flow._id}` : "#"}
                className="text-blue-600 dark:text-blue-400 hover:underline ms-2"
              >
                {flow._id}
              </Link>
              {flow.time && (
                <span className="text-gray-500 dark:text-gray-400 text-xs ms-2">
                  {new Date(flow.time).toLocaleString()}
                </span>
              )}
            </li>
          ))}
          {flows.length > 5 && (
            <li className="text-gray-500 dark:text-gray-400 text-xs">
              +{flows.length - 5} more
            </li>
          )}
        </ul>
      </div>
    </section>
  );
}
