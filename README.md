Frontend is [here](https://github.com/that-one-arab/stoic-diary-frontend)

# How to run:
- Make sure docker and docker-compose are installed
- Create a `.env`file in the project's root directly, modify the file referencing the provided `.env.example` and save the newly modified `.env` file
- Open a terminal and go to the project's root directory
- Run docker-compose up inside the terminal

That's pretty much it.

You can start developing immediately since django supports hot reloads (except when you create a new file that's when you'll have to restart the django server, I'd rather just restart the docker containers), have fun!
