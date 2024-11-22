import Joi, { ObjectSchema } from 'joi';

// Register Schema
export const registerSchema: ObjectSchema = Joi.object({
  username: Joi.string().min(3).max(30).required().messages({
    'string.empty': 'Username is required',
    'string.min': 'Username must be at least 3 characters long',
    'string.max': 'Username cannot be more than 30 characters',
  }),
  password: Joi.string().min(6).required().messages({
    'string.empty': 'Password is required',
    'string.min': 'Password must be at least 6 characters long',
  }),
  confirmPassword: Joi.string().valid(Joi.ref('password')).required().messages({
    'string.empty': 'Confirm password is required',
    'any.only': 'Passwords must match',
  }),
});

// Login Schema
export const loginSchema: ObjectSchema = Joi.object({
  username: Joi.string().required().messages({
    'string.empty': 'Username is required',
  }),
  password: Joi.string().required().messages({
    'string.empty': 'Password is required',
  }),
});

// Logout Schema
export const logoutSchema: ObjectSchema = Joi.object().empty().messages({
  'object.base': 'No data should be sent for logout',
});
