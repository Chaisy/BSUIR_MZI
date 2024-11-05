import math


class Point:

    def __init__(self, x, y):
        self.x = x
        self.y = y

    def equal(self, other_point):
        return self.x == other_point.x and self.y == other_point.y

    def is_infinity(self):
        return self.x == -1 and self.y == -1

    def __str__(self):
        return str(self.x) + "," + str(self.y)


class EllipticCurve:
    """
    y^2 = (x^3 + ax + b) mod p
    """

    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

    def addition(self, first_point, second_point):

        if first_point.is_infinity():
            return Point(second_point.x, second_point.y)
        if second_point.is_infinity():
            return Point(first_point.x, first_point.y)


        if first_point.equal(second_point):
            return self.self_addition(first_point)

        else:
            if first_point.x == second_point.x:
                # Inf
                return Point(-1, -1)
            else:
                delta_x = (first_point.x - second_point.x)
                gradient = ((first_point.y - second_point.y) * self.__modulo_invers(delta_x)) % self.p
                new_x = (gradient ** 2 - (first_point.x + second_point.x)) % self.p
                new_y = (gradient * (first_point.x - new_x) - first_point.y) % self.p

                return Point(new_x, new_y)

    def self_addition(self, point):
        if point.y == 0:
            return Point(-1, -1)
        else:

            gradient = ((3 * (point.x ** 2) + self.a) * self.__modulo_invers(2 * point.y)) % self.p
            new_x = (gradient ** 2 - 2 * point.x) % self.p
            new_y = (gradient * (point.x - new_x) - point.y) % self.p

            return Point(new_x, new_y)

    def multiplication(self, point, constant):
        if constant == 1:
            return Point(point.x, point.y)
        if constant % 2 == 0:
            return self.self_addition(self.multiplication(point, math.floor(constant / 2)))
        else:
            temp_point = self.multiplication(self.multiplication(point, math.floor(constant / 2)), 2)

            return self.addition(temp_point, point)

    def __modulo_invers(self, num):
        for i in range(1, self.p):
            if (num * i) % self.p == 1:
                return i

        return 0

    def generatePoints(self, x):
        temp_list = []
        remainder = self.y(x)
        for y in range(1, self.p):
            if y ** 2 % self.p == remainder:
                temp_list.append(y)

        return temp_list

    def y(self, x):
        return (x ** 3 + self.a * x + self.b) % self.p