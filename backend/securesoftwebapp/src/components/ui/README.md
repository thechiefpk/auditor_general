UI primitives exported:

- `Button` – props: `variant` (primary|secondary|ghost), `size` (sm|md|lg), `disabled`
- `Input` – basic input with focus styling
- `Card` – simple white card container
- `Table` – responsive table wrapper
- `Modal` – accessible modal with Escape-to-close
- `Badge` – small status badge
- `Toast` – notification item (used by `ToastProvider`)

Usage:
import { Button, Card } from './components/ui';

These mirror Tailwind tokens in `tailwind.config.cjs`.
