declare const __DAE_DEV_API_URL__: string;

declare module "dae-theme" {
  export const theme: typeof import("./theme.ts").theme;
}

declare module "dae-theme.css";
