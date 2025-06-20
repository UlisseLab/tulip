import { useSearchParams } from "react-router";

export function useSearchParam<T>(
  key: string,
  initialValue: T,
  urlify: (value: T) => string | null,
  deurlify: (value: string) => T
): [T, (value: T | null) => void] {
  const [searchParams, setSearchParams] = useSearchParams();

  const urlValue = searchParams.get(key);
  const value: T = urlValue === null ? initialValue : deurlify(urlValue);

  const setValue = (newValue: T | null) =>
    setSearchParams((prev) => {
      const params = new URLSearchParams(prev);

      const newUrlValue = newValue === null ? null : urlify(newValue);
      if (newUrlValue === null) {
        params.delete(key);
      } else {
        params.set(key, newUrlValue);
      }

      return params;
    });

  return [value, setValue];
}
