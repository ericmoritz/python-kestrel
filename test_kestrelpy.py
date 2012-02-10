import unittest
import kestrelpy


SERVERS = ["localhost:22133"]


class TestFlush(unittest.TestCase):
    def test(self):
        c = kestrelpy.Client(SERVERS)
        c.add("queue", "test")
        c.flush("queue")

        self.assertEqual(c.get("queue"), None)


class TestAdd(unittest.TestCase):
    def test(self):
        c = kestrelpy.Client(SERVERS)
        c.flush("queue")
        c.add("queue", "test")
        
        self.assertEqual(c.get("queue"), "test")


class TestGet(unittest.TestCase):
    def test(self):
        c = kestrelpy.Client(SERVERS)
        c.flush("queue")
        c.add("queue", "test")
    
        self.assertEqual(c.get("queue"), "test")
        self.assertEqual(c.get("queue"), None)


class TestAll(unittest.TestCase):
    def test(self):
        c = kestrelpy.Client(SERVERS)
        c.flush("queue")

        c.add("queue", "test1")
        c.add("queue", "test2")
    
        self.assertEqual(c.next("queue"), "test1")
        self.assertEqual(c.next("queue"), "test2")
        c.abort("queue")
        self.assertEqual(c.peek("queue"), "test2")
        self.assertEqual(c.next("queue"), "test2")
        self.assertEqual(c.next("queue"), None)        

        c.add("queue", "test1")
        self.assertEqual(c.next("queue"), "test1")
        c.finish("queue")
        self.assertEqual(c.next("queue"), None)
