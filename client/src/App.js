import React, { lazy, Suspense } from "react";
import { BrowserRouter as Router, Switch, Route } from "react-router-dom";
// components
import * as ROUTES from "./constants/routes";
import Loading from "./components/loading/Loading";
// pages
const Login = lazy(() => import("./pages/login/Login"));
const Signup = lazy(() => import("./pages/signup/Signup"));
const Home = lazy(() => import("./pages/home/Home"));
const ERROR_404 = lazy(() => import("./pages/error_404/Error_404"));

function App() {
  return (
    <Router>
      <Suspense fallback={<Loading />}>
        <Switch>
          <Route exact path={ROUTES.LOGIN} component={Login} />
          <Route exact path={ROUTES.SIGNUP} component={Signup} />
          <Route exact path={ROUTES.HOME} component={Home} />
          <Route component={ERROR_404} />
        </Switch>
      </Suspense>
    </Router>
  );
}

export default App;
