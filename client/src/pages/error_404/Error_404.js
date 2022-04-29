import React from "react";
import { useHistory } from "react-router-dom";
import "./Error_404.css";
// constants
import { HOME } from "../../constants/routes";
import { ERROR_404 } from "../../constants/images";
// material-ui icons
import AssignmentRoundedIcon from '@material-ui/icons/AssignmentRounded';
import ArrowBackIosRoundedIcon from '@material-ui/icons/ArrowBackIosRounded';

const Error_404 = () => {
    const history = useHistory();

    return (
        <div className="error_404">
            <div className="error_404__box">
                <img src={ERROR_404} alt="" />
                <h1>404 - Page Not Found !</h1>
                <h2>Looks like the page you are searching for doesn't exist...</h2>
                <div className="error_404__links">
                    <button className="error_404__link" onClick={() => history.push(HOME)}>
                        <AssignmentRoundedIcon />
                        <p>Home</p>
                    </button>
                    <button className="error_404__link" onClick={() => history.goBack()}>
                        <ArrowBackIosRoundedIcon />
                        <p>Back</p>
                    </button>
                </div>
            </div>
        </div>
    );
};

export default Error_404;
