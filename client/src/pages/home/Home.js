import React, { useEffect } from "react";
import { useHistory } from "react-router-dom";
import axios from "axios";
import "./Home.css";
// constants
import { LOGIN } from "../../constants/routes";
import { HAPPY } from "../../constants/images";
// material-ui
import { Button } from "@material-ui/core";

const TOKEN_AUTH_ENDPOINT = "http://localhost:8000/token";

const Home = () => {
    const history = useHistory();

    useEffect(() => {
        try {
            const { token } = JSON.parse(localStorage.getItem("task5_token"));

            axios.post(TOKEN_AUTH_ENDPOINT, { token }).then(res => {
                if (!res.data.userId)
                    history.push(LOGIN);
            }).catch(() => history.push(LOGIN));
        } catch (err) { history.push(LOGIN); };

    }, [history]);

    const handleLogout = () => {
        localStorage.removeItem("task5_token");
        history.push(LOGIN);
    };

    return (
        <div className="home">
            <div className="home__box">
                <img className="home__happyGifLeft" src={HAPPY} alt="" />
                <div className="home__options">
                    <h1>Congratulations!</h1>
                    <h2>You have successfully logged<br />into your account...</h2>
                    <Button onClick={() => handleLogout()}>Logout</Button>
                </div>
                <img className="home__happyGifRight" src={HAPPY} alt="" />
            </div>
        </div>
    );
};

export default Home;
