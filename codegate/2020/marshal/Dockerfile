FROM ubuntu:18.04

# Setup environ
ENV user r2jail
ENV prob_port 7777

# Install packages
RUN apt-get update
RUN apt-get install -y git make gcc build-essential socat afl

# Change permission
RUN chmod 1733 /tmp /var/tmp /dev/shm

ENV CC afl-gcc

# Additional configuration
RUN adduser $user
ADD ./binary_flag/run.sh /home/$user/run.sh
ADD ./binary_flag/build_r2.sh /home/$user/build_r2.sh
ADD ./binary_flag/patch.diff /home/$user/patch.diff
ADD ./binary_flag/flag /home/$user/flag

# Build and install r2
RUN chown -R root:root /home/$user/
RUN chown root:$user /home/$user/run.sh
RUN chown root:$user /home/$user/flag
RUN chown root:$user /home/$user/patch.diff

RUN chmod 2755 /home/$user/run.sh
RUN chmod 440 /home/$user/flag
RUN chmod 440 /home/$user/patch.diff
RUN chmod 550 /home/$user/build_r2.sh

WORKDIR /home/$user
RUN ./build_r2.sh

# final
CMD socat -T 5 TCP-LISTEN:$prob_port,reuseaddr,fork EXEC:/home/$user/run.sh
USER $user
EXPOSE $prob_port
