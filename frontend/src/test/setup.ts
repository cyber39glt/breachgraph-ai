import "@testing-library/jest-dom/vitest";
import { cleanup } from "@testing-library/react";
import { afterEach } from "vitest";

// Unmount rendered components after every test (Vitest globals are off, so do it explicitly).
afterEach(() => cleanup());
