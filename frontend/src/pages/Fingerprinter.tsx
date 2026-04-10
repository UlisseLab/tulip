import { useParams } from "react-router";
import { useGetFlowsQuery } from "../api";
import { Link } from "react-router";

export function Fingerprinter() {
  const { id } = useParams();

  const idNumber = parseInt(id || "", 10);
  const isIdInvalid = isNaN(idNumber);

  const { data, error, isLoading } = useGetFlowsQuery(
    { fingerprints: [idNumber] },
    { skip: isIdInvalid },
  );

  if (isIdInvalid) {
    return (
      <div className="flex justify-center items-center h-[60vh]">
        <span className="text-4xl font-bold text-red-500">Invalid ID</span>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex justify-center items-center h-[60vh]">
        <span className="text-4xl font-bold">Loading...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex justify-center items-center h-[60vh]">
        <span className="text-4xl font-bold text-red-500">
          Error: {JSON.stringify(error)}
        </span>
      </div>
    );
  }

  if (!data || !data.data || data.data.length === 0) {
    return (
      <div className="flex justify-center items-center h-[60vh]">
        <span className="text-2xl font-semibold text-gray-500">
          No data found for this fingerprint.
        </span>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto mt-10">
      <h2 className="text-3xl font-bold mb-6 text-center">
        Timeline for Fingerprint {idNumber}
      </h2>
      <ol className="relative border-l-2 border-blue-500">
        {data.data.map((item, idx) => (
          <li key={item._id || idx} className="mb-10 ml-6">
            <Link
              to={`/flow/${item._id}`}
              className="no-underline"
              key={item._id || idx}
            >
              <span className="absolute -left-3 flex items-center justify-center w-6 h-6 bg-blue-500 rounded-full ring-8 ring-white">
                <svg
                  className="w-3 h-3 text-white"
                  fill="currentColor"
                  viewBox="0 0 20 20"
                >
                  <circle cx="10" cy="10" r="10" />
                </svg>
              </span>
              <div className="flex flex-col gap-1">
                <span className="text-lg font-semibold">
                  {`Event ${idx + 1}`}
                </span>
                {item.time && (
                  <span className="text-sm text-gray-400">
                    {new Date(item.time).toLocaleString()}
                  </span>
                )}
              </div>
            </Link>
          </li>
        ))}
      </ol>
    </div>
  );
}
