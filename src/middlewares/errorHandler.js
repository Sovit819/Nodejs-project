import ApiError from "../utils/ApiError.js";

const errorHandler = (err, req, res, next) => {

    let statusCode = err.statusCode || 500;
    let message = err.message || "Internal Server Error";
    let errors = [];

    // Mongoose Validation Error
    if (err.name === 'ValidationError') {
        statusCode = 400;

        const validationMessages = Object.values(err.errors)
            .map(val => val.message);

        message = "Validation Failed: " + validationMessages.join(' | ');

        errors = Object.values(err.errors).map(val => ({
            path: val.path,
            message: val.message
        }));
    }

    else if (err.name === "CastError") {
        statusCode = 400;
        message = `Invalid ${err.path}: ${err.value}`;
        errors = [{
            path: err.path,
            message: `Invalid ID format. Please check the provided ID.`
        }];
    }

    // Mongoose Duplicate Key Error (11000)
    else if (err.code === 11000) {
        statusCode = 409;
        const value = Object.keys(err.keyValue)[0];
        message = `The value '${err.keyValue[value]}' already exists for the field '${value}'. Please use another value.`;
        errors = [{ path: value, message }];
    }

    // Custom ApiError
    else if (err instanceof ApiError) {
        statusCode = err.statusCode;
        message = err.message;
        errors = err.error;
    }
    // Final Response Structure
    const finalErrors = (Array.isArray(errors) && errors.length > 0) ? errors : [{ message: message }];

    return res.status(statusCode).json({
        statusCode,
        success: false,
        message,
        errors: finalErrors
    });
};

export default errorHandler;