import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route, Outlet } from "react-router";
import { useHotkeys } from "react-hotkeys-hook";

// @ts-expect-error - we should fix type declarations
import "@fontsource-variable/recursive";
// @ts-expect-error - we should fix type declarations
import "@fontsource-variable/jetbrains-mono";

import "./styles.css";

import { Header } from "./components/Header";
import { Home } from "./pages/Home";

import { FlowList } from "./components/FlowList";
import { FlowView } from "./pages/FlowView";

const DiffView = lazy(() => import("./pages/DiffView"));
const Corrie = lazy(() => import("./components/Corrie"));

function App() {
  useHotkeys("esc", () => (document.activeElement as HTMLElement).blur(), {
    enableOnFormTags: true,
  });

  return (
    <BrowserRouter>
      <Routes>
        <Route path="/" element={<Layout />}>
          <Route index element={<Home />} />
          <Route
            path="flow/:id"
            element={
              <Suspense>
                <FlowView />
              </Suspense>
            }
          />
          <Route
            path="diff/:id"
            element={
              <Suspense>
                <DiffView />
              </Suspense>
            }
          />
          <Route
            path="corrie/"
            element={
              <Suspense>
                <Corrie />
              </Suspense>
            }
          />
        </Route>
        <Route path="*" element={<PageNotFound />} />
      </Routes>
    </BrowserRouter>
  );
}

function Layout() {
  return (
    <div className="grid-container">
      <header className="header-area">
        <Header></Header>
      </header>
      <aside className="flow-list-area">
        <Suspense>
          <FlowList></FlowList>
        </Suspense>
      </aside>
      <main className="flow-details-area">
        <Outlet />
      </main>
      <footer className="footer-area"></footer>
    </div>
  );
}

function PageNotFound() {
  return (
    <div>
      <h2>404 Page not found</h2>
    </div>
  );
}

export default App;
