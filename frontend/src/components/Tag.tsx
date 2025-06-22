import classNames from "classnames";
import Color from "color";

const computeColorFromString = (str: string) => {
  const hue = Array.from(str).reduce(
    (hash, char) => 0 | (31 * hash + char.charCodeAt(0)),
    0,
  );
  return Color(`hsl(${hue}, 100%, 50%)`).hex();
};

// Hardcode colors here
const tagColorMap: Record<string, string> = {
  fishy: "rgb(191, 219, 254)",
  blocked: "rgb(233, 213, 255)",
  flag_out: "rgb(254, 204, 204)",
  flag_in: "rgb(209, 213, 219)",
};

export function tagToColor(tag: string) {
  return tagColorMap[tag] ?? computeColorFromString(tag);
}
interface TagProps {
  tag: string;
  color?: string;
  disabled?: boolean;
  excluded?: boolean;
  onClick?: () => void;
}
export const Tag = ({
  tag,
  color,
  disabled = false,
  excluded = false,
  onClick,
}: TagProps) => {
  let tagBackgroundColor = disabled ? undefined : (color ?? tagToColor(tag));
  let tagTextColor = disabled
    ? undefined
    : Color(tagBackgroundColor ?? "#eee").isDark()
      ? "#fff"
      : "#000";

  if (excluded) {
    tagTextColor = "white";
    tagBackgroundColor = "black";
  }

  return (
    <div
      onClick={onClick}
      className={classNames(
        "p-3 cursor-pointer rounded-md uppercase text-xs h-5 text-center flex items-center hover:opacity-90 transition-colors duration-250 text-ellipsis overflow-hidden whitespace-nowrap border",
        {
          "bg-gray-300 dark:bg-gray-700 text-gray-500 dark:text-gray-300 border-gray-400 dark:border-gray-600": disabled,
          "border-black dark:border-white": excluded,
        },
      )}
      style={{
        backgroundColor: tagBackgroundColor,
        color: tagTextColor,
      }}
    >
      <span
        className={classNames({
          "line-through": excluded,
        })}
      >
        {tag}
      </span>
    </div>
  );
};
