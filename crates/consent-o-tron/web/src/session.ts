import { createContext, useContext } from "react";
import type { User } from "./api";

export type SessionValue = {
  /** `undefined` while loading, `null` when logged out. */
  user: User | null | undefined;
  setUser: (u: User | null) => void;
  /** Opens the login dialog, then runs `then` once logged in. */
  requireLogin: (then?: (u: User) => void) => void;
  /** NotSSL, where people get the certificate their wallet identity needs. */
  certSite: string;
};

export const Session = createContext<SessionValue>({ user: undefined, setUser: () => {}, requireLogin: () => {}, certSite: "http://localhost:4001" });

export const useSession = () => useContext(Session);

/** Moves to another page of the app without reloading. */
export function go(path: string, { scroll = true } = {}) {
  history.pushState(null, "", path);
  dispatchEvent(new PopStateEvent("popstate"));
  if (scroll) scrollTo(0, 0);
}
