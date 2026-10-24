import "./style.css";
import { loginAvailable } from "./api.ts";
import { followColorScheme } from "./color-mode.ts";

followColorScheme();
if (loginAvailable) void import("./app.ts");
else void import("./setup.tsx");
