import { app } from './app';
import { APP_PORT } from './config';

const port = APP_PORT;

// Start the server
app.listen(port, () => {
    console.log(`Server is running on Port# ${port}`);
});

