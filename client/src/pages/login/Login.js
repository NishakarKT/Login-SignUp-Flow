import React, { useState, useEffect } from "react";
import { Link, useHistory } from "react-router-dom";
import validator from "validator";
import "./Login.css";
// costants
import { HOME, SIGNUP } from "../../constants/routes";
// components
import Loading from "../../components/loading/Loading";
import SecureInput from "../../components/secureInput/SecureInput";
// material-ui
import { TextField, Button } from "@material-ui/core";
import axios from "axios";

const AUTH_ENDPOINT = "http://localhost:8000/auth";
const TOKEN_AUTH_ENDPOINT = "http://localhost:8000/token";

const Login = () => {
    const history = useHistory();
    // states
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    // errors
    const [emailErr, setEmailErr] = useState(false);
    const [passwordErr, setPasswordErr] = useState(false);

    useEffect(() => {
        try {
            const { token } = JSON.parse(localStorage.getItem("task5_token"));

            axios.post(TOKEN_AUTH_ENDPOINT, { token }).then(res => {
                if (res.data.userId)
                    history.push(HOME);
            }).catch(() => { });
        } catch (err) { }
    }, [history]);

    const handleLogin = (e) => {
        e.preventDefault();

        setEmailErr(!validator.isEmail(email));
        setPasswordErr(!password);

        if (validator.isEmail(email) && password) {
            setIsLoading(true);
            const userCreds = { email, password };

            axios.post(AUTH_ENDPOINT, userCreds).then(res => {
                if (res.data.auth) {
                    localStorage.setItem("task5_token", JSON.stringify({ token: res.data.token }));
                    history.push(HOME);
                }
                else {
                    alert("User access : DENIED !");
                    setIsLoading(false);
                }
            }).catch(() => { setIsLoading(false); });

            // reset
            setPassword("");
            e.target.reset();
        }
    };

    return (
        <div className="login">
            {isLoading ? <Loading /> : null}
            <form className="login__box" onSubmit={(e) => handleLogin(e)}>
                <p className="login__title">Login</p>
                <TextField
                    label="Email"
                    error={emailErr}
                    helperText={emailErr ? "What's your valid email ?" : null}
                    onChange={(e) => setEmail(e.target.value)} />
                <SecureInput label="Password" error={passwordErr} helperText="What's your password ?" input={password} setInput={setPassword} />
                <Button type="submit">Login</Button>
                <Link className="login__signupLink" to={SIGNUP}>New Account</Link>
            </form>
        </div>
    );
};

export default Login;
