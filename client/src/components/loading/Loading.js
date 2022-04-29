import React from 'react';
import "./Loading.css"
// constants
import { LOADING } from "../../constants/images";

const Loading = () => {
    return (
        <div className="loading">
            <img src={LOADING} alt="" />
        </div>
    );
};

export default Loading;
