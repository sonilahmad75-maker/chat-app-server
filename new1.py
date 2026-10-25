import socketio
import socketio
so=socketio.Client()
so.connect("http://127.0.0.1:5000/send_message",headers={"Authorization":"Bearer eyJ1c2VyX2lkIjoxfQ.atnszw.xBt3BHyNJNbUVBCqgdMKeMey_EI"})
so.emit("send_message", {"message": "Hello, World!"})

so.wait()

