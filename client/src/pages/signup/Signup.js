import React, { useState, useEffect } from "react";
import validator from "validator";
import { v4 as uuidv4 } from "uuid";
import axios from "axios";
import { Link, useHistory } from "react-router-dom";
import "./Signup.css";
// constants
import { LOGIN, HOME } from "../../constants/routes";
// components
import Loading from "../../components/loading/Loading";
import SecureInput from "../../components/secureInput/SecureInput";
// material-ui
import { TextField, Button } from "@material-ui/core";

const NEW_ENDPOINT = "http://localhost:8000/new";
const TOKEN_AUTH_ENDPOINT = "http://localhost:8000/token";

const Signup = () => {
    const history = useHistory();
    // states
    const [fName, setFname] = useState("");
    const [lName, setLname] = useState("");
    const [city, setCity] = useState("");
    const [email, setEmail] = useState("");
    const [password, setPassword] = useState("");
    const [isLoading, setIsLoading] = useState(false);
    // errors
    const [fNameErr, setFnameErr] = useState(false);
    const [lNameErr, setLnameErr] = useState(false);
    const [cityErr, setCityErr] = useState(false);
    const [emailErr, setEmailErr] = useState(false);
    const [passwordErr, setPasswordErr] = useState(false);

    useEffect(() => {
        try {
            const { token } = JSON.parse(localStorage.getItem("task5_token"));

            axios.post(TOKEN_AUTH_ENDPOINT, { token }).then(res => {
                if (res.data.userId)
                    history.push(HOME);
            }).catch(() => { });
        } catch (err) { };

    }, [history]);

    const handleSignup = (e) => {
        e.preventDefault();

        setFnameErr(!fName);
        setLnameErr(!lName);
        setCityErr(!city);
        setEmailErr(!validator.isEmail(email));
        setPasswordErr(!password);

        if (fName && lName && city && validator.isEmail(email) && password) {
            setIsLoading(true);
            const userData = {
                userId: uuidv4(), // to generate unique data id, but in case of mongo db, we already have a unique id created
                firstName: fName,
                lastName: lName,
                city: city,
                email: email,
                password: password
            };

            axios.post(NEW_ENDPOINT, userData).then(res => {
                localStorage.setItem("task5_token", JSON.stringify({ token: res.data }));
                e.target.reset();
                history.push(HOME);
                alert(`Congratulations ${fName}, You are registered!`);
            }).catch(() => {
                setIsLoading(false);
                alert("Email already exists.")
            });

            // reset
            setPassword("");
        }
    };

    return (
        <div className="signup">
            {isLoading ? <Loading /> : null}
            <form className="signup__box" onSubmit={(e) => handleSignup(e)}>
                <p className="signup__title">Signup</p>
                <TextField
                    label="First Name"
                    error={fNameErr}
                    helperText={fNameErr ? "What's your first name ?" : null}
                    onChange={(e) => setFname(e.target.value)} />
                <TextField
                    label="Last Name"
                    error={lNameErr}
                    helperText={lNameErr ? "What's your last name ?" : null}
                    onChange={(e) => setLname(e.target.value)} />
                <TextField
                    label="City"
                    error={cityErr}
                    helperText={cityErr ? "Where do you live ?" : null}
                    onChange={(e) => setCity(e.target.value)} />
                <TextField
                    label="Email"
                    error={emailErr}
                    helperText={emailErr ? "What's your valid email ?" : null}
                    onChange={(e) => setEmail(e.target.value)} />
                <SecureInput label="Password" error={passwordErr} helperText="Where's your password ?" input={password} setInput={setPassword} />
                <Button type="submit">Signup</Button>
                <Link className="signup__loginLink" to={LOGIN}>Have Account?</Link>
            </form>
        </div>
    );
};

export default Signup;
