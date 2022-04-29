import React, { useState } from "react";
import "./SecureInput.css";
// material-ui
import { TextField } from "@material-ui/core";
import VisibilityRoundedIcon from '@material-ui/icons/VisibilityRounded';
import VisibilityOffRoundedIcon from '@material-ui/icons/VisibilityOffRounded';

const SecureInput = ({ label, error, helperText, input, setInput }) => {
    const [visibility, setVisibility] = useState(false);

    return (
        <div className="secureInput" >
            <TextField
                value={input}
                label={label}
                type={visibility ? "text" : "password"}
                error={error}
                helperText={error ? helperText : ""}
                onChange={(e) => setInput(e.target.value)}
            />
            {visibility ? <VisibilityRoundedIcon onClick={() => setVisibility(!visibility)} /> : <VisibilityOffRoundedIcon onClick={() => setVisibility(!visibility)} />}
        </div>
    );
};

export default SecureInput;
