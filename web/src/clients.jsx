import { createView } from "./react-view.js";

function ClientSets({ device, actions }) {
  if (!device.sets.length) return <p className="muted">No routing options available for this device.</p>;
  return <div className="client-options">{device.sets.map(set => {
    const label = set.description || set.name;
    return <div key={set.name} className="set-row" data-name={set.name}>
      <strong>{label}</strong>
      <button type="button" className="client-toggle" role="switch" aria-checked={set.joined} aria-label={label} onClick={() => actions.run(async () => {
        actions.update(await actions.request(`/api/device/sets/${encodeURIComponent(set.name)}`, set.joined ? "DELETE" : "PUT"));
      }, `${label} turned ${set.joined ? "off" : "on"} for this device.`)}>
        <span className="switch-track" aria-hidden="true" /><span aria-hidden="true">{set.joined ? "On" : "Off"}</span>
      </button>
    </div>;
  })}</div>;
}

export function createClientSets(container, actions) {
  const render = createView(container);
  return {
    show: (device) => render(<ClientSets key={`${device.mac}/${device.source_ip}`} device={device} actions={actions} />),
    error: (text) => render(<p className="muted">{text}</p>),
  };
}
