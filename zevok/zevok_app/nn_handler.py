from tensorflow.keras.models import load_model


model = load_model('/Users/pavelbandurovskij/PycharmProjects/dip/yawn/zevok/zevok_app/model.h5')
emotion = ["angry", "disgust", "fear", "happy", "sad", "yawning", "neutral"]

def evaluate(data, label):
    model.evaluate(x=data, y=label, batch_size=32, verbose=1)

def predict(data):
    emotion_list = model.predict(data)
    pred_list = [prob for lst in emotion_list for prob in lst]
    pred_dict = dict(zip(emotion, pred_list))
    print(pred_dict)
    sorted_by_value = sorted(pred_dict.items(), key=lambda kv: kv[1], reverse=True)
    print(sorted_by_value)
    return sorted_by_value[0][0]
