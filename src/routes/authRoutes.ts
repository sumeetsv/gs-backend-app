import { Router } from 'express';
import { validateRequest } from '../middleware/validateRequest';
import { login, logout, refreshToken, registerUser } from '../controllers/authController'; // Assuming controllers are in authController
import { loginSchema, logoutSchema, registerSchema } from '../validators/authValidators';

const router = Router();

router.post('/register', validateRequest(registerSchema), registerUser);
router.post('/login', validateRequest(loginSchema), login);
router.post('/logout', validateRequest(logoutSchema), logout);
router.post('/refreshToken', refreshToken);

export default router;
