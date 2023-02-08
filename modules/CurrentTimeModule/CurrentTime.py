import datetime


class CurrentTime:
    @classmethod
    def get_current_time(cls):
        # return datetime to string
        return datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")


if __name__ == '__main__':
    print(CurrentTime.get_current_time())
