import classNames from "classnames";

export type RadioGroupProps = {
  options: string[];
  value: string;
  className: string;
  onChange: (option: string) => void;
};

export function RadioGroup({
  className,
  onChange,
  options,
  value,
}: RadioGroupProps) {
  return (
    <div className={className}>
      {options.map((option) => (
        <div
          key={option}
          onClick={() => onChange(option)}
          className={classNames("py-1 px-2 rounded-md cursor-pointer", {
            "bg-gray-200": option === value,
          })}
        >
          {option}
        </div>
      ))}
    </div>
  );
}
