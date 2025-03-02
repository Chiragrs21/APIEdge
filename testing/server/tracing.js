const { NodeSDK } = require("@opentelemetry/sdk-node");
const {
  getNodeAutoInstrumentations,
} = require("@opentelemetry/auto-instrumentations-node");
const { PrometheusExporter } = require("@opentelemetry/exporter-prometheus");
const {
  OTLPTraceExporter,
} = require("@opentelemetry/exporter-trace-otlp-http");
const { ConsoleSpanExporter } = require("@opentelemetry/sdk-trace-base");

const prometheusExporter = new PrometheusExporter(
  { port: 9464, startServer: true },
  () => console.log("✅ Prometheus metrics: http://localhost:9464/metrics")
);

// Trace Exporter (Use OTLP for Jaeger/Zipkin OR Console for debugging)
const traceExporter = new OTLPTraceExporter({
  url: "http://localhost:4318/v1/traces", // Ensure OpenTelemetry Collector is running
});

// OpenTelemetry SDK setup
const sdk = new NodeSDK({
  traceExporter: traceExporter, // Use correct trace exporter
  metricExporter: prometheusExporter, // Metrics collection
  instrumentations: [getNodeAutoInstrumentations()],
});

sdk.start();
console.log("✅ OpenTelemetry Tracing & Metrics initialized");
