import classNames from "classnames";

export type RadioGroupProps<T extends string = string> = {
  options: readonly T[];
  value: T;
  className: string;
  onChange: (option: T) => void;
};

export function RadioGroup<T extends string>({
  className,
  onChange,
  options,
  value,
}: RadioGroupProps<T>) {
  return (
    <div className={className}>
      {options.map((option) => (
        <div
          key={option}
          tabIndex={0}
          onClick={() => onChange(option)}
          onKeyDown={(e) => {
            if (e.key === "Enter" || e.key === " ") onChange(option);
          }}
          className={classNames(
            "py-1 px-2 rounded-md border border-gray-300 dark:border-gray-700 cursor-pointer outline-none transition-colors",
            "text-gray-800 dark:text-gray-100",
            {
              "bg-gray-200 dark:bg-gray-700 font-semibold ring-blue-400 dark:ring-blue-300": option === value,
              "hover:bg-gray-100 dark:hover:bg-gray-800": option !== value,
            },
          )}
        >
          {option}
        </div>
      ))}
    </div>
  );
}
