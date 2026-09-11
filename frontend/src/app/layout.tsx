import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "KavachRecon - Attack Surface Intelligence",
  description: "Authorized attack surface management and reconnaissance platform",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased min-h-screen bg-zinc-950 text-zinc-100">
        {children}
      </body>
    </html>
  );
}
