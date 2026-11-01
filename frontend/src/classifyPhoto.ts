import type { MobileNet } from "@tensorflow-models/mobilenet";
import type { DetectedObject, ObjectDetection } from "@tensorflow-models/coco-ssd";

type Prediction = { className: string; probability: number };
type Category = "Animals" | "People" | "Food" | "Nature" | "Travel" | "Other";
type DetectionCategory = Extract<Category, "Animals" | "People" | "Food">;

let modelPromise: Promise<MobileNet> | null = null;
let detectorPromise: Promise<ObjectDetection> | null = null;
let classificationQueue: Promise<void> = Promise.resolve();

function getModels(): Promise<[MobileNet, ObjectDetection]> {
  if (!modelPromise || !detectorPromise) {
    const loading = Promise.all([
      import("@tensorflow/tfjs"),
      import("@tensorflow-models/mobilenet"),
      import("@tensorflow-models/coco-ssd")
    ])
      .then(async ([tf, mobilenet, cocoSsd]) => {
        await tf.ready();
        const [classifier, detector] = await Promise.all([
          mobilenet.load({ version: 2, alpha: 0.5 }),
          cocoSsd.load({ base: "lite_mobilenet_v2" })
        ]);
        return [classifier, detector] as [MobileNet, ObjectDetection];
      });
    const retryOnFailure = loading.catch((error: unknown) => {
      modelPromise = null;
      detectorPromise = null;
      throw error;
    });
    modelPromise = retryOnFailure.then(([classifier]) => classifier);
    detectorPromise = retryOnFailure.then(([, detector]) => detector);
  }
  return Promise.all([modelPromise, detectorPromise]);
}

const normalized = (label: string) => ` ${label.toLowerCase().replace(/[^a-z0-9]+/g, " ").trim()} `;

function hasTerm(label: string, terms: string[]) {
  const paddedLabel = normalized(label);
  return terms.some((term) => paddedLabel.includes(normalized(term)));
}

export function categoryFromDetections(detections: DetectedObject[]): Category | null {
  const animals = ["bird", "cat", "dog", "horse", "sheep", "cow", "elephant", "bear", "zebra", "giraffe"];
  const food = ["banana", "apple", "sandwich", "orange", "broccoli", "carrot", "hot dog", "pizza", "donut", "cake"];
  const ranked = detections
    .map((detection) => {
      const [x, y, width, height] = detection.bbox;
      const area = Math.max(0, width * height);
      const category: DetectionCategory | null = detection.class === "person"
        ? "People"
        : animals.includes(detection.class)
          ? "Animals"
          : food.includes(detection.class)
            ? "Food"
            : null;
      return { category, score: detection.score * Math.sqrt(area) };
    })
    .filter((detection): detection is { category: DetectionCategory; score: number } =>
      detection.category !== null
    )
    .sort((a, b) => b.score - a.score);
  return ranked[0]?.category ?? null;
}

function categoryFromPredictions(predictions: Prediction[]): Category {
  const labels = predictions
    .filter((prediction) => prediction.probability >= 0.08)
    .map((prediction) => prediction.className);
  const matches = (terms: string[]) => labels.some((label) => hasTerm(label, terms));

  if (matches([
    "dog", "cat", "kitten", "puppy", "bird", "horse", "hamster", "rabbit", "pet", "terrier",
    "retriever", "poodle", "shepherd", "fox", "wolf", "lion", "tiger", "monkey", "deer",
    "squirrel", "turtle", "snake", "lizard", "fish", "whale", "dolphin", "bear", "elephant",
    "zebra", "giraffe", "cow", "sheep", "pig", "goat", "chicken", "duck", "butterfly", "bee"
  ])) return "Animals";
  if (matches([
    "person", "people", "bride", "groom", "boy", "girl", "man", "woman", "athlete", "player",
    "swimmer", "performer", "worker", "waiter", "waitress", "barber", "nurse", "doctor",
    "teacher", "student", "customer", "passenger", "face", "headshot"
  ])) return "People";
  if (matches(["food", "pizza", "burger", "hot dog", "sandwich", "dessert", "cake", "ice cream", "espresso", "soup", "plate", "bowl", "fruit", "banana", "apple", "orange"])) return "Food";
  if (matches(["flower", "tree", "forest", "mountain", "valley", "beach", "seashore", "ocean", "lake", "waterfall", "sky", "landscape", "volcano", "coral reef", "promontory"])) return "Nature";
  if (matches(["castle", "palace", "monument", "church", "mosque", "temple", "landmark", "bridge", "tower", "building", "dam", "lighthouse"])) return "Travel";
  return "Other";
}

export function classifyPhoto(image: Blob): Promise<Category> {
  const task = classificationQueue.then(async () => {
    let source: ImageBitmap | HTMLImageElement;
    let objectUrl: string | null = null;
    try {
      source = await createImageBitmap(image);
    } catch {
      objectUrl = URL.createObjectURL(image);
      const imageElement = new Image();
      imageElement.src = objectUrl;
      try {
        await imageElement.decode();
        source = imageElement;
      } catch {
        URL.revokeObjectURL(objectUrl);
        throw new Error("This image format could not be decoded for on-device categorization.");
      }
    }

    const width = source instanceof ImageBitmap ? source.width : source.naturalWidth;
    const height = source instanceof ImageBitmap ? source.height : source.naturalHeight;
    const scale = Math.min(1, 512 / Math.max(width, height));
    const canvas = document.createElement("canvas");
    canvas.width = Math.max(1, Math.round(width * scale));
    canvas.height = Math.max(1, Math.round(height * scale));

    try {
      const context = canvas.getContext("2d");
      if (!context) throw new Error("Unable to prepare image for on-device categorization.");
      context.drawImage(source, 0, 0, canvas.width, canvas.height);
      const [classifier, detector] = await getModels();
      const detections = await detector.detect(canvas, 20, 0.25);
      const detectedCategory = categoryFromDetections(detections);
      if (detectedCategory) return detectedCategory;
      const predictions = await classifier.classify(canvas, 5);
      return categoryFromPredictions(predictions);
    } finally {
      if (source instanceof ImageBitmap) source.close();
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    }
  });

  classificationQueue = task.then(() => undefined, () => undefined);
  return task;
}
