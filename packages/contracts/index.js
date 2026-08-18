export const TelemetrySchema = { name: "TelemetryEvent", validate: (d) => !!d.id && !!d.status };
